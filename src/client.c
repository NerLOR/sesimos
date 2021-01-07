/**
 * Necronda Web Server
 * Client connection and request handlers
 * src/client.c
 * Lorenz Stechauner, 2020-12-03
 */

#include "necronda-server.h"
#include "utils.h"
#include "uri.h"
#include "http.h"
#include "fastcgi.h"


int server_keep_alive = 1;
char *client_addr_str, *client_addr_str_ptr, *server_addr_str, *server_addr_str_ptr,
        *log_client_prefix, *log_conn_prefix, *log_req_prefix,
        *client_host_str, *client_geoip;

struct timeval client_timeout = {.tv_sec = CLIENT_TIMEOUT, .tv_usec = 0};

host_config *get_host_config(const char *host) {
    for (int i = 0; i < MAX_HOST_CONFIG; i++) {
        host_config *hc = &config[i];
        if (hc->type == CONFIG_TYPE_UNSET) break;
        if (strcmp(hc->name, host) == 0) return hc;
    }
    return NULL;
}

void client_terminate() {
    server_keep_alive = 0;
}

int client_websocket_handler() {
    // TODO implement client_websocket_handler
    return 0;
}

int client_request_handler(sock *client, unsigned long client_num, unsigned int req_num) {
    struct timespec begin, end;
    long ret;
    int client_keep_alive;
    char buf0[1024], buf1[1024];
    char msg_buf[4096], msg_pre_buf[4096], err_msg[256];
    char buffer[CHUNK_SIZE];
    err_msg[0] = 0;
    char host[256], *host_ptr, *hdr_connection;
    host_config *conf = NULL;
    long content_length = 0;
    FILE *file = NULL;
    msg_buf[0] = 0;
    int accept_if_modified_since = 0;
    int use_fastcgi = 0;
    int use_rev_proxy = 0;
    fastcgi_conn php_fpm = {.socket = 0, .req_id = 0};
    http_status custom_status;

    http_res res;
    sprintf(res.version, "1.1");
    res.status = http_get_status(501);
    res.hdr.field_num = 0;
    http_add_header_field(&res.hdr, "Date", http_get_date(buf0, sizeof(buf0)));
    http_add_header_field(&res.hdr, "Server", SERVER_STR);

    clock_gettime(CLOCK_MONOTONIC, &begin);

    fd_set socket_fds;
    FD_ZERO(&socket_fds);
    FD_SET(client->socket, &socket_fds);
    client_timeout.tv_sec = CLIENT_TIMEOUT;
    client_timeout.tv_usec = 0;
    ret = select(client->socket + 1, &socket_fds, NULL, NULL, &client_timeout);
    if (ret <= 0) {
        if (errno != 0) {
            return 1;
        }
        client_keep_alive = 0;
        res.status = http_get_status(408);
        goto respond;
    }
    clock_gettime(CLOCK_MONOTONIC, &begin);

    http_req req;
    ret = http_receive_request(client, &req);
    if (ret != 0) {
        client_keep_alive = 0;
        if (ret < 0) {
            goto abort;
        } else if (ret == 1) {
            sprintf(err_msg, "Unable to parse header: Invalid header format.");
        } else if (ret == 2) {
            sprintf(err_msg, "Unable to parse header: Invalid method.");
        } else if (ret == 3) {
            sprintf(err_msg, "Unable to parse header: Invalid version.");
        } else if (ret == 4) {
            sprintf(err_msg, "Unable to parse header: Header contains illegal characters.");
        } else if (ret == 5) {
            sprintf(err_msg, "Unable to parse header: End of header not found.");
        }
        res.status = http_get_status(400);
        goto respond;
    }

    hdr_connection = http_get_header_field(&req.hdr, "Connection");
    client_keep_alive = hdr_connection != NULL &&
            (strcmp(hdr_connection, "keep-alive") == 0 || strcmp(hdr_connection, "Keep-Alive") == 0);
    host_ptr = http_get_header_field(&req.hdr, "Host");
    if (host_ptr != NULL && strlen(host_ptr) > 255) {
        host[0] = 0;
        res.status = http_get_status(400);
        sprintf(err_msg, "Host header field is too long.");
        goto respond;
    } else if (host_ptr == NULL || strchr(host_ptr, '/') != NULL) {
        if (strchr(client_addr_str, ':') == NULL) {
            strcpy(host, client_addr_str);
        } else {
            sprintf(host, "[%s]", client_addr_str);
        }
        res.status = http_get_status(400);
        sprintf(err_msg, "The client provided no or an invalid Host header field.");
        goto respond;
    } else {
        strcpy(host, host_ptr);
    }

    sprintf(log_req_prefix, "[%s%24s%s]%s ", BLD_STR, host, CLR_STR, log_client_prefix);
    log_prefix = log_req_prefix;
    print(BLD_STR "%s %s" CLR_STR, req.method, req.uri);

    conf = get_host_config(host);
    if (conf == NULL) {
        print("Host unknown, redirecting to default");
        res.status = http_get_status(307);
        sprintf(buf0, "https://%s%s", DEFAULT_HOST, req.uri);
        http_add_header_field(&res.hdr, "Location", buf0);
        goto respond;
    }

    http_uri uri;
    unsigned char dir_mode = conf->type == CONFIG_TYPE_LOCAL ? conf->local.dir_mode : URI_DIR_MODE_NO_VALIDATION;
    ret = uri_init(&uri, conf->local.webroot, req.uri, dir_mode);
    if (ret != 0) {
        if (ret == 1) {
            sprintf(err_msg, "Invalid URI: has to start with slash.");
        } else if (ret == 2) {
            sprintf(err_msg, "Invalid URI: contains relative path change (/../).");
        }
        res.status = http_get_status(400);
        goto respond;
    }

    if (dir_mode != URI_DIR_MODE_NO_VALIDATION) {
        ssize_t size = sizeof(buf0);
        url_decode(req.uri, buf0, &size);
        int change_proto = strncmp(uri.uri, "/.well-known/", 13) != 0 && !client->enc;
        if (strcmp(uri.uri, buf0) != 0 || change_proto) {
            res.status = http_get_status(308);
            size = sizeof(buf0);
            encode_url(uri.uri, buf0, &size);
            if (change_proto) {
                sprintf(buf1, "https://%s%s", host, buf0);
                http_add_header_field(&res.hdr, "Location", buf1);
            } else {
                http_add_header_field(&res.hdr, "Location", buf0);
            }
            goto respond;
        }
    }

    if (conf->type == CONFIG_TYPE_LOCAL) {
        if (uri.filename == NULL && (int) uri.is_static && (int) uri.is_dir && strlen(uri.pathinfo) == 0) {
            res.status = http_get_status(403);
            sprintf(err_msg, "It is not allowed to list the contents of this directory.");
            goto respond;
        } else if (uri.filename == NULL && (int) !uri.is_static && (int) uri.is_dir && strlen(uri.pathinfo) == 0) {
            // TODO list directory contents
            res.status = http_get_status(501);
            sprintf(err_msg, "Listing contents of an directory is currently not implemented.");
            goto respond;
        } else if (uri.filename == NULL || (strlen(uri.pathinfo) > 0 && (int) uri.is_static)) {
            res.status = http_get_status(404);
            goto respond;
        } else if (strlen(uri.pathinfo) != 0 && conf->local.dir_mode != URI_DIR_MODE_INFO) {
            res.status = http_get_status(404);
            goto respond;
        }

        if (uri.is_static) {
            res.status = http_get_status(200);
            http_add_header_field(&res.hdr, "Allow", "GET, HEAD");
            http_add_header_field(&res.hdr, "Accept-Ranges", "bytes");
            if (strcmp(req.method, "GET") != 0 && strcmp(req.method, "HEAD") != 0) {
                res.status = http_get_status(405);
                goto respond;
            }

            ret = uri_cache_init(&uri);
            if (ret != 0) {
                res.status = http_get_status(500);
                sprintf(err_msg, "Unable to communicate with internal file cache.");
                goto respond;
            }
            char *last_modified = http_format_date(uri.meta->stat.st_mtime, buf0, sizeof(buf0));
            http_add_header_field(&res.hdr, "Last-Modified", last_modified);
            sprintf(buf1, "%s; charset=%s", uri.meta->type, uri.meta->charset);
            http_add_header_field(&res.hdr, "Content-Type", buf1);
            if (uri.meta->etag[0] != 0) {
                http_add_header_field(&res.hdr, "ETag", uri.meta->etag);
            }
            if (strncmp(uri.meta->type, "text/", 5) == 0) {
                http_add_header_field(&res.hdr, "Cache-Control", "public, max-age=3600");
            } else {
                http_add_header_field(&res.hdr, "Cache-Control", "public, max-age=86400");
            }

            char *if_modified_since = http_get_header_field(&req.hdr, "If-Modified-Since");
            char *if_none_match = http_get_header_field(&req.hdr, "If-None-Match");
            if ((if_none_match != NULL && strstr(if_none_match, uri.meta->etag) == NULL) ||
                (accept_if_modified_since && if_modified_since != NULL && strcmp(if_modified_since, last_modified) == 0)) {
                res.status = http_get_status(304);
                goto respond;
            }

            char *range = http_get_header_field(&req.hdr, "Range");
            if (range != NULL) {
                if (strlen(range) <= 6 || strncmp(range, "bytes=", 6) != 0) {
                    res.status = http_get_status(416);
                    http_remove_header_field(&res.hdr, "Content-Type", HTTP_REMOVE_ALL);
                    http_remove_header_field(&res.hdr, "Last-Modified", HTTP_REMOVE_ALL);
                    http_remove_header_field(&res.hdr, "ETag", HTTP_REMOVE_ALL);
                    http_remove_header_field(&res.hdr, "Cache-Control", HTTP_REMOVE_ALL);
                    goto respond;
                }
                range += 6;
                char *ptr = strchr(range, '-');
                if (ptr == NULL) {
                    res.status = http_get_status(416);
                    goto respond;
                }
                file = fopen(uri.filename, "rb");
                fseek(file, 0, SEEK_END);
                unsigned long file_len = ftell(file);
                fseek(file, 0, SEEK_SET);
                if (file_len == 0) {
                    content_length = 0;
                    goto respond;
                }
                long num1 = 0;
                long num2 = (long) file_len - 1;

                if (ptr != range) num1 = (long) strtoul(range, NULL, 10);
                if (ptr[1] != 0) num2 = (long) strtoul(ptr + 1, NULL, 10);

                if (num1 >= file_len || num2 >= file_len || num1 > num2) {
                    res.status = http_get_status(416);
                    goto respond;
                }
                sprintf(buf0, "bytes %li-%li/%li", num1, num2, file_len);
                http_add_header_field(&res.hdr, "Content-Range", buf0);

                res.status = http_get_status(206);
                fseek(file, num1, SEEK_SET);
                content_length = num2 - num1 + 1;

                goto respond;
            }

            char *accept_encoding = http_get_header_field(&req.hdr, "Accept-Encoding");
            if (uri.meta->filename_comp[0] != 0 && accept_encoding != NULL &&
                strstr(accept_encoding, "deflate") != NULL) {
                file = fopen(uri.meta->filename_comp, "rb");
                if (file == NULL) {
                    cache_filename_comp_invalid(uri.filename);
                    goto not_compressed;
                }
                http_add_header_field(&res.hdr, "Content-Encoding", "deflate");
            } else {
                not_compressed:
                file = fopen(uri.filename, "rb");
            }
            fseek(file, 0, SEEK_END);
            content_length = ftell(file);
            fseek(file, 0, SEEK_SET);
        } else {
            struct stat statbuf;
            stat(uri.filename, &statbuf);
            char *last_modified = http_format_date(statbuf.st_mtime, buf0, sizeof(buf0));
            http_add_header_field(&res.hdr, "Last-Modified", last_modified);

            res.status = http_get_status(200);
            if (fastcgi_init(&php_fpm, client_num, req_num, client, &req, &uri) != 0) {
                res.status = http_get_status(502);
                sprintf(err_msg, "Unable to communicate with PHP-FPM.");
                goto respond;
            }

            if (strcmp(req.method, "POST") == 0 || strcmp(req.method, "PUT") == 0) {
                char *client_content_length = http_get_header_field(&req.hdr, "Content-Length");
                unsigned long client_content_len;
                if (client_content_length == NULL) {
                    goto fastcgi_end;
                }
                client_content_len = strtoul(client_content_length, NULL, 10);
                ret = fastcgi_receive(&php_fpm, client, client_content_len);
                if (ret != 0) {
                    if (ret < 0) {
                        goto abort;
                    } else {
                        sprintf(err_msg, "Unable to communicate with PHP-FPM.");
                    }
                    res.status = http_get_status(502);
                    goto respond;
                }
            }
            fastcgi_end:
            fastcgi_close_stdin(&php_fpm);

            ret = fastcgi_header(&php_fpm, &res, err_msg);
            if (ret != 0) {
                if (ret < 0) {
                    goto abort;
                }
                goto respond;
            }
            char *status = http_get_header_field(&res.hdr, "Status");
            if (status != NULL) {
                int status_code = (int) strtoul(status, NULL, 10);
                res.status = http_get_status(status_code);
                http_remove_header_field(&res.hdr, "Status", HTTP_REMOVE_ALL);
                if (res.status == NULL && status_code >= 100 && status_code <= 999) {
                    custom_status.code = status_code;
                    strcpy(custom_status.type, "");
                    strcpy(custom_status.msg, status + 4);
                    res.status = &custom_status;
                } else if (res.status == NULL) {
                    res.status = http_get_status(500);
                    sprintf(err_msg, "The status code was set to an invalid or unknown value.");
                    goto respond;
                }
            }

            char *accept_encoding = http_get_header_field(&req.hdr, "Accept-Encoding");
            if (accept_encoding != NULL && strstr(accept_encoding, "deflate") != NULL) {
                http_add_header_field(&res.hdr, "Content-Encoding", "deflate");
            }

            content_length = -1;
            use_fastcgi = 1;
            if (http_get_header_field(&res.hdr, "Content-Length") == NULL) {
                http_add_header_field(&res.hdr, "Transfer-Encoding", "chunked");
            }
        }
    } else if (conf->type != CONFIG_TYPE_LOCAL) {
        print("Reverse proxy for " BLD_STR "%s:%i" CLR_STR, conf->rev_proxy.hostname, conf->rev_proxy.port);
        ret = rev_proxy_init(&req, &res, conf, client, &custom_status, err_msg);
        use_rev_proxy = ret == 0;
    } else {
        print(ERR_STR "Unknown host type: %i" CLR_STR, conf->type);
        res.status = http_get_status(501);
    }

    respond:
    if (!use_rev_proxy) {
        if (http_get_header_field(&res.hdr, "Accept-Ranges") == NULL) {
            http_add_header_field(&res.hdr, "Accept-Ranges", "none");
        }
        if (!use_fastcgi && !use_rev_proxy && file == NULL &&
            res.status->code >= 400 && res.status->code < 600) {
            http_error_msg *http_msg = http_get_error_msg(res.status->code);
            sprintf(msg_pre_buf, http_error_document, res.status->code, res.status->msg,
                    http_msg != NULL ? http_msg->err_msg : "", err_msg[0] != 0 ? err_msg : "");
            content_length = sprintf(msg_buf, http_default_document, res.status->code, res.status->msg,
                                     msg_pre_buf, res.status->code >= 300 && res.status->code < 400 ? "info" : "error",
                                     http_error_icon, "#C00000", host);
            http_add_header_field(&res.hdr, "Content-Type", "text/html; charset=UTF-8");
        }
        if (content_length >= 0) {
            sprintf(buf0, "%li", content_length);
            http_add_header_field(&res.hdr, "Content-Length", buf0);
        } else if (http_get_header_field(&res.hdr, "Transfer-Encoding") == NULL) {
            server_keep_alive = 0;
        }
    } else {
        http_remove_header_field(&res.hdr, "Server", HTTP_REMOVE_ALL);
        http_remove_header_field(&res.hdr, "Date", HTTP_REMOVE_ALL);
        http_add_header_field(&res.hdr, "Date", http_get_date(buf0, sizeof(buf0)));
        http_add_header_field(&res.hdr, "Server", SERVER_STR);
    }
    char *conn = http_get_header_field(&res.hdr, "Connection");
    int close_proxy = conn == NULL || (strcmp(conn, "keep-alive") != 0 && strcmp(conn, "Keep-Alive") != 0);
    http_remove_header_field(&res.hdr, "Connection", HTTP_REMOVE_ALL);
    http_remove_header_field(&res.hdr, "Keep-Alive", HTTP_REMOVE_ALL);
    if (server_keep_alive && client_keep_alive) {
        http_add_header_field(&res.hdr, "Connection", "keep-alive");
        sprintf(buf0, "timeout=%i, max=%i", CLIENT_TIMEOUT, REQ_PER_CONNECTION);
        http_add_header_field(&res.hdr, "Keep-Alive", buf0);
    } else {
        http_add_header_field(&res.hdr, "Connection", "close");
    }

    http_send_response(client, &res);
    clock_gettime(CLOCK_MONOTONIC, &end);
    char *location = http_get_header_field(&res.hdr, "Location");
    unsigned long micros = (end.tv_nsec - begin.tv_nsec) / 1000 + (end.tv_sec - begin.tv_sec) * 1000000;
    print("%s%s%03i %s%s%s (%s)%s", http_get_status_color(res.status), use_rev_proxy ? "-> " : "", res.status->code,
          res.status->msg, location != NULL ? " -> " : "", location != NULL ? location : "",
          format_duration(micros, buf0), CLR_STR);

    if (strcmp(req.method, "HEAD") != 0) {
        unsigned long snd_len = 0;
        unsigned long len;
        if (msg_buf[0] != 0) {
            ret = sock_send(client, msg_buf, content_length, 0);
            if (ret <= 0) {
                print(ERR_STR "Unable to send: %s" CLR_STR, sock_strerror(client));
            }
            snd_len += ret;
        } else if (file != NULL) {
            while (snd_len < content_length) {
                len = fread(buffer, 1, CHUNK_SIZE, file);
                if (snd_len + len > content_length) {
                    len = content_length - snd_len;
                }
                sock_send(client, buffer, len, feof(file) ? 0 : MSG_MORE);
                if (ret <= 0) {
                    print(ERR_STR "Unable to send: %s" CLR_STR, sock_strerror(client));
                    break;
                }
                snd_len += ret;
            }
        } else if (use_fastcgi) {
            char *transfer_encoding = http_get_header_field(&res.hdr, "Transfer-Encoding");
            int chunked = transfer_encoding != NULL && strcmp(transfer_encoding, "chunked") == 0;
            char *content_encoding = http_get_header_field(&res.hdr, "Content-Encoding");
            int comp = content_encoding != NULL && strcmp(content_encoding, "deflate") == 0;
            int flags = (chunked ? FASTCGI_CHUNKED : 0) | (comp ? FASTCGI_COMPRESS : 0);
            fastcgi_send(&php_fpm, client, flags);
        } else if (use_rev_proxy) {
            char *transfer_encoding = http_get_header_field(&res.hdr, "Transfer-Encoding");
            int chunked = transfer_encoding != NULL && strcmp(transfer_encoding, "chunked") == 0;
            char *content_len = http_get_header_field(&res.hdr, "Content-Length");
            unsigned long len_to_send = 0;
            if (content_len != NULL) {
                len_to_send = strtol(content_len, NULL, 10);
            }
            rev_proxy_send(client, chunked, len_to_send);
        }
    }

    if (close_proxy && rev_proxy.socket != 0) {
        print(BLUE_STR "Closing proxy connection" CLR_STR);
        sock_close(&rev_proxy);
    }

    fflush(stdout);

    clock_gettime(CLOCK_MONOTONIC, &end);
    micros = (end.tv_nsec - begin.tv_nsec) / 1000 + (end.tv_sec - begin.tv_sec) * 1000000;
    print("Transfer complete: %s", format_duration(micros, buf0));

    uri_free(&uri);
    abort:
    if (php_fpm.socket != 0) {
        shutdown(php_fpm.socket, SHUT_RDWR);
        close(php_fpm.socket);
        php_fpm.socket = 0;
    }
    http_free_req(&req);
    http_free_res(&res);
    if (client->buf != NULL) {
        free(client->buf);
        client->buf = NULL;
        client->buf_off = 0;
        client->buf_len = 0;
    }
    return !client_keep_alive;
}

int client_connection_handler(sock *client, unsigned long client_num) {
    struct timespec begin, end;
    int ret, req_num;
    char buf[1024];

    clock_gettime(CLOCK_MONOTONIC, &begin);

    if (dns_server[0] != 0) {
        sprintf(buf, "dig @%s +short +time=1 -x %s", dns_server, client_addr_str);
        FILE *dig = popen(buf, "r");
        if (dig == NULL) {
            print(ERR_STR "Unable to start dig: %s" CLR_STR "\n", strerror(errno));
            goto dig_err;
        }
        unsigned long read = fread(buf, 1, sizeof(buf), dig);
        ret = pclose(dig);
        if (ret != 0) {
            print(ERR_STR "Dig terminated with exit code %i" CLR_STR "\n", ret);
            goto dig_err;
        }
        char *ptr = memchr(buf, '\n', read);
        if (ptr == buf || ptr == NULL) {
            goto dig_err;
        }
        ptr[-1] = 0;
        client_host_str = malloc(strlen(buf) + 1);
        strcpy(client_host_str, buf);
    } else {
        dig_err:
        client_host_str = NULL;
    }

    client_geoip = malloc(GEOIP_MAX_SIZE);
    long str_off = 0;
    for (int i = 0; i < MAX_MMDB && mmdbs[i].filename != NULL; i++) {
        int gai_error, mmdb_res;
        MMDB_lookup_result_s result = MMDB_lookup_string(&mmdbs[i], client_addr_str, &gai_error, &mmdb_res);
        if (mmdb_res != MMDB_SUCCESS) {
            print(ERR_STR "Unable to lookup geoip info: %s" CLR_STR "\n", MMDB_strerror(mmdb_res));
            continue;
        } else if (gai_error != 0) {
            print(ERR_STR "Unable to lookup geoip info" CLR_STR "\n");
            continue;
        } else if (!result.found_entry) {
            continue;
        }

        MMDB_entry_data_list_s *list;
        mmdb_res = MMDB_get_entry_data_list(&result.entry, &list);
        if (mmdb_res != MMDB_SUCCESS) {
            print(ERR_STR "Unable to lookup geoip info: %s" CLR_STR "\n", MMDB_strerror(mmdb_res));
            continue;
        }

        long prev = str_off;
        if (str_off != 0) {
            str_off--;
        }
        mmdb_json(list, client_geoip, &str_off, GEOIP_MAX_SIZE);
        if (prev != 0) {
            client_geoip[prev - 1] = ',';
        }

        MMDB_free_entry_data_list(list);
    }

    char client_cc[3];
    client_cc[0] = 0;
    if (str_off == 0) {
        free(client_geoip);
        client_geoip = NULL;
    } else {
        char *pos = client_geoip;
        pos = strstr(pos, "\"country\":");
        if (pos != NULL) {
            pos = strstr(pos, "\"iso_code\":");
            pos += 12;
            strncpy(client_cc, pos, 2);
        }
    }

    print("Connection accepted from %s %s%s%s[%s]", client_addr_str, client_host_str != NULL ? "(" : "",
          client_host_str != NULL ? client_host_str : "", client_host_str != NULL ? ") " : "",
          client_cc[0] != 0 ? client_cc : "N/A");

    client_timeout.tv_sec = CLIENT_TIMEOUT;
    client_timeout.tv_usec = 0;
    if (setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout)) < 0)
        goto set_timeout_err;
    if (setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout)) < 0) {
        set_timeout_err:
        print(ERR_STR "Unable to set timeout for socket: %s" CLR_STR, strerror(errno));
        return 1;
    }

    if (client->enc) {
        client->ssl = SSL_new(client->ctx);
        SSL_set_fd(client->ssl, client->socket);
        SSL_set_accept_state(client->ssl);

        ret = SSL_accept(client->ssl);
        client->_last_ret = ret;
        client->_errno = errno;
        client->_ssl_error = ERR_get_error();
        if (ret <= 0) {
            print(ERR_STR "Unable to perform handshake: %s" CLR_STR, sock_strerror(client));
            goto close;
        }
    }

    req_num = 0;
    ret = 0;
    while (ret == 0 && server_keep_alive && req_num < REQ_PER_CONNECTION) {
        ret = client_request_handler(client, client_num, req_num++);
        log_prefix = log_conn_prefix;
    }

    close:
    sock_close(client);

    if (rev_proxy.socket != 0) {
        print(BLUE_STR "Closing proxy connection" CLR_STR);
        sock_close(&rev_proxy);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    unsigned long micros = (end.tv_nsec - begin.tv_nsec) / 1000 + (end.tv_sec - begin.tv_sec) * 1000000;

    print("Connection closed (%s)", format_duration(micros, buf));
    return 0;
}

int client_handler(sock *client, unsigned long client_num, struct sockaddr_in6 *client_addr) {
    int ret;
    struct sockaddr_in6 *server_addr;
    struct sockaddr_storage server_addr_storage;

    char *color_table[] = {"\x1B[31m", "\x1B[32m", "\x1B[33m", "\x1B[34m", "\x1B[35m", "\x1B[36m"};

    signal(SIGINT, client_terminate);
    signal(SIGTERM, client_terminate);

    client_addr_str_ptr = malloc(INET6_ADDRSTRLEN);
    inet_ntop(client_addr->sin6_family, (void *) &client_addr->sin6_addr, client_addr_str_ptr, INET6_ADDRSTRLEN);
    if (strncmp(client_addr_str_ptr, "::ffff:", 7) == 0) {
        client_addr_str = client_addr_str_ptr + 7;
    } else {
        client_addr_str = client_addr_str_ptr;
    }

    socklen_t len = sizeof(server_addr_storage);
    getsockname(client->socket, (struct sockaddr *) &server_addr_storage, &len);
    server_addr = (struct sockaddr_in6 *) &server_addr_storage;
    server_addr_str_ptr = malloc(INET6_ADDRSTRLEN);
    inet_ntop(server_addr->sin6_family, (void *) &server_addr->sin6_addr, server_addr_str_ptr, INET6_ADDRSTRLEN);
    if (strncmp(server_addr_str_ptr, "::ffff:", 7) == 0) {
        server_addr_str = server_addr_str_ptr + 7;
    } else {
        server_addr_str = server_addr_str_ptr;
    }

    log_req_prefix = malloc(256);
    log_client_prefix = malloc(256);
    sprintf(log_client_prefix, "[%s%4i%s]%s[%*s][%5i]%s", (int) client->enc ? HTTPS_STR : HTTP_STR,
            ntohs(server_addr->sin6_port), CLR_STR, color_table[client_num % 6], INET_ADDRSTRLEN, client_addr_str,
            ntohs(client_addr->sin6_port), CLR_STR);

    log_conn_prefix = malloc(256);
    sprintf(log_conn_prefix, "[%24s]%s ", server_addr_str, log_client_prefix);
    log_prefix = log_conn_prefix;

    print("Started child process with PID %i", getpid());

    ret = client_connection_handler(client, client_num);
    free(client_addr_str_ptr);
    client_addr_str_ptr = NULL;
    free(server_addr_str_ptr);
    server_addr_str_ptr = NULL;
    if (client_host_str != NULL) {
        free(client_host_str);
        client_host_str = NULL;
    }
    free(log_conn_prefix);
    log_conn_prefix = NULL;
    free(log_req_prefix);
    log_req_prefix = NULL;
    free(log_client_prefix);
    log_client_prefix = NULL;
    return ret;
}
