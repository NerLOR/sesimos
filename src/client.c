/**
 * sesimos - secure, simple, modern web server
 * Client connection and request handlers
 * src/client.c
 * Lorenz Stechauner, 2020-12-03
 */

#include "defs.h"
#include "client.h"
#include "server.h"

#include "lib/utils.h"
#include "lib/config.h"
#include "lib/sock.h"
#include "lib/http.h"
#include "lib/rev_proxy.h"
#include "lib/fastcgi.h"
#include "lib/cache.h"
#include "lib/geoip.h"
#include "lib/compress.h"
#include "lib/websocket.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <arpa/inet.h>


int server_keep_alive = 1;
struct timeval client_timeout = {.tv_sec = CLIENT_TIMEOUT, .tv_usec = 0};

char *log_client_prefix, *log_conn_prefix, *log_req_prefix, *client_geoip;
char *client_addr_str, *client_addr_str_ptr, *server_addr_str, *server_addr_str_ptr, *client_host_str;

host_config *get_host_config(const char *host) {
    for (int i = 0; i < CONFIG_MAX_HOST_CONFIG; i++) {
        host_config *hc = &config->hosts[i];
        if (hc->type == CONFIG_TYPE_UNSET) break;
        if (strcmp(hc->name, host) == 0) return hc;
        if (hc->name[0] == '*' && hc->name[1] == '.') {
            const char *pos = strstr(host, hc->name + 1);
            if (pos != NULL && strlen(pos) == strlen(hc->name + 1)) return hc;
        }
    }
    return NULL;
}

void client_terminate() {
    server_keep_alive = 0;
}

int client_request_handler(sock *client, unsigned long client_num, unsigned int req_num) {
    struct timespec begin, end;
    long ret;
    int client_keep_alive;

    char buf0[1024], buf1[1024];
    char msg_buf[8192], msg_pre_buf_1[4096], msg_pre_buf_2[4096], err_msg[256];
    char msg_content[1024];
    char buffer[CHUNK_SIZE];
    char host[256];
    const char *host_ptr, *hdr_connection;

    msg_buf[0] = 0;
    err_msg[0] = 0;
    msg_content[0] = 0;

    host_config *conf = NULL;
    FILE *file = NULL;

    long content_length = 0;
    int accept_if_modified_since = 0;
    int use_fastcgi = 0;
    int use_rev_proxy = 0;
    int p_len;

    fastcgi_conn fcgi_conn = {.socket = 0, .req_id = 0};
    http_status custom_status;

    http_res res = {.version = "1.1", .status = http_get_status(501), .hdr.field_num = 0, .hdr.last_field_num = -1};
    http_status_ctx ctx = {.status = 0, .origin = NONE, .ws_key = NULL};

    clock_gettime(CLOCK_MONOTONIC, &begin);

    ret = sock_poll_read(&client, NULL, 1, CLIENT_TIMEOUT * 1000);

    http_add_header_field(&res.hdr, "Date", http_get_date(buf0, sizeof(buf0)));
    http_add_header_field(&res.hdr, "Server", SERVER_STR);
    if (ret <= 0) {
        if (errno != 0) return 1;

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
            sprintf(err_msg, "Unable to parse http header: Invalid header format.");
        } else if (ret == 2) {
            sprintf(err_msg, "Unable to parse http header: Invalid method.");
        } else if (ret == 3) {
            sprintf(err_msg, "Unable to parse http header: Invalid version.");
        } else if (ret == 4) {
            sprintf(err_msg, "Unable to parse http header: Header contains illegal characters.");
        } else if (ret == 5) {
            sprintf(err_msg, "Unable to parse http header: End of header not found.");
        }
        res.status = http_get_status(400);
        goto respond;
    }

    hdr_connection = http_get_header_field(&req.hdr, "Connection");
    client_keep_alive = (hdr_connection != NULL && (strstr(hdr_connection, "keep-alive") != NULL || strstr(hdr_connection, "Keep-Alive") != NULL));
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

    sprintf(log_req_prefix, "[%6i][%s%*s%s]%s ", getpid(), BLD_STR, INET6_ADDRSTRLEN, host, CLR_STR, log_client_prefix);
    log_prefix = log_req_prefix;
    print(BLD_STR "%s %s" CLR_STR, req.method, req.uri);

    conf = get_host_config(host);
    if (conf == NULL) {
        print("Unknown host, redirecting to default");
        res.status = http_get_status(307);
        sprintf(buf0, "https://%s%s", DEFAULT_HOST, req.uri);
        http_add_header_field(&res.hdr, "Location", buf0);
        goto respond;
    }

    http_uri uri;
    unsigned char dir_mode = (conf->type == CONFIG_TYPE_LOCAL ? conf->local.dir_mode : URI_DIR_MODE_NO_VALIDATION);
    ret = uri_init(&uri, conf->local.webroot, req.uri, dir_mode);
    if (ret != 0) {
        if (ret == 1) {
            sprintf(err_msg, "Invalid URI: has to start with slash.");
            res.status = http_get_status(400);
        } else if (ret == 2) {
            sprintf(err_msg, "Invalid URI: contains relative path change (/../).");
            res.status = http_get_status(400);
        } else if (ret == 3) {
            sprintf(err_msg, "The specified webroot directory does not exist.");
            res.status = http_get_status(404);
        } else {
            res.status = http_get_status(500);
        }
        goto respond;
    }

    if (dir_mode != URI_DIR_MODE_NO_VALIDATION) {
        ssize_t size = sizeof(buf0);
        url_decode(req.uri, buf0, &size);
        int change_proto = strncmp(uri.uri, "/.well-known/", 13) != 0 && !client->enc;
        if (strcmp(uri.uri, buf0) != 0 || change_proto) {
            res.status = http_get_status(308);
            size = sizeof(buf0);
            url_encode(uri.uri, buf0, &size);
            if (change_proto) {
                p_len = snprintf(buf1, sizeof(buf1), "https://%s%s", host, buf0);
                if (p_len < 0 || p_len >= sizeof(buf1)) {
                    res.status = http_get_status(500);
                    print(ERR_STR "Header field 'Location' too long" CLR_STR);
                    goto respond;
                }
                http_add_header_field(&res.hdr, "Location", buf1);
            } else {
                http_add_header_field(&res.hdr, "Location", buf0);
            }
            goto respond;
        }
    } else if (!client->enc) {
        res.status = http_get_status(308);
        sprintf(buf0, "https://%s%s", host, req.uri);
        http_add_header_field(&res.hdr, "Location", buf0);
        goto respond;
    }

    if (http_get_header_field(&req.hdr, "Transfer-Encoding") != NULL) {
        sprintf(err_msg, "This server is unable to process requests with the Transfer-Encoding header field.");
        res.status = http_get_status(501);
        goto respond;
    }

    if (conf->type == CONFIG_TYPE_LOCAL) {
        if (strcmp(req.method, "TRACE") == 0) {
            res.status = http_get_status(200);
            http_add_header_field(&res.hdr, "Content-Type", "message/http");

            content_length = snprintf(msg_buf, sizeof(msg_buf) - content_length, "%s %s HTTP/%s\r\n", req.method, req.uri, req.version);
            for (int i = 0; i < req.hdr.field_num; i++) {
                const http_field *f = &req.hdr.fields[i];
                content_length += snprintf(msg_buf + content_length, sizeof(msg_buf) - content_length, "%s: %s\r\n", http_field_get_name(f), http_field_get_value(f));
            }

            goto respond;
        }

        if (strncmp(uri.req_path, "/.well-known/", 13) == 0) {
            http_add_header_field(&res.hdr, "Access-Control-Allow-Origin", "*");
        }

        if (strncmp(uri.req_path, "/.well-known/", 13) != 0 && strstr(uri.path, "/.") != NULL) {
            res.status = http_get_status(403);
            sprintf(err_msg, "Parts of this URI are hidden.");
            goto respond;
        } else if (uri.filename == NULL && (int) uri.is_static && (int) uri.is_dir && strlen(uri.pathinfo) == 0) {
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
            http_add_header_field(&res.hdr, "Accept-Ranges", "bytes");
            if (strcmp(req.method, "GET") != 0 && strcmp(req.method, "HEAD") != 0) {
                res.status = http_get_status(405);
                goto respond;
            }

            if (http_get_header_field(&req.hdr, "Content-Length") != NULL) {
                res.status = http_get_status(400);
                sprintf(err_msg, "A GET request must not contain a payload");
                goto respond;
            }

            ret = uri_cache_init(&uri);
            if (ret != 0) {
                res.status = http_get_status(500);
                sprintf(err_msg, "Unable to communicate with internal file cache.");
                goto respond;
            }
            const char *last_modified = http_format_date(uri.meta->stat.st_mtime, buf0, sizeof(buf0));
            http_add_header_field(&res.hdr, "Last-Modified", last_modified);
            sprintf(buf1, "%s; charset=%s", uri.meta->type, uri.meta->charset);
            http_add_header_field(&res.hdr, "Content-Type", buf1);


            const char *accept_encoding = http_get_header_field(&req.hdr, "Accept-Encoding");
            int enc = 0;
            if (accept_encoding != NULL) {
                if (uri.meta->filename_comp_br[0] != 0 && strstr(accept_encoding, "br") != NULL) {
                    file = fopen(uri.meta->filename_comp_br, "rb");
                    if (file == NULL) {
                        cache_filename_comp_invalid(uri.filename);
                    } else {
                        http_add_header_field(&res.hdr, "Content-Encoding", "br");
                        enc = COMPRESS_BR;
                    }
                } else if (uri.meta->filename_comp_gz[0] != 0 && strstr(accept_encoding, "gzip") != NULL) {
                    file = fopen(uri.meta->filename_comp_gz, "rb");
                    if (file == NULL) {
                        cache_filename_comp_invalid(uri.filename);
                    } else {
                        http_add_header_field(&res.hdr, "Content-Encoding", "gzip");
                        enc = COMPRESS_GZ;
                    }
                }
                if (enc != 0) {
                    http_add_header_field(&res.hdr, "Vary", "Accept-Encoding");
                }
            }

            if (uri.meta->etag[0] != 0) {
                if (enc) {
                    sprintf(buf0, "%s-%s", uri.meta->etag, (enc & COMPRESS_BR) ? "br" : (enc & COMPRESS_GZ) ? "gzip" : "");
                    http_add_header_field(&res.hdr, "ETag", buf0);
                } else {
                    http_add_header_field(&res.hdr, "ETag", uri.meta->etag);
                }
            }

            if (strncmp(uri.meta->type, "text/", 5) == 0) {
                http_add_header_field(&res.hdr, "Cache-Control", "public, max-age=3600");
            } else {
                http_add_header_field(&res.hdr, "Cache-Control", "public, max-age=86400");
            }

            const char *if_modified_since = http_get_header_field(&req.hdr, "If-Modified-Since");
            const char *if_none_match = http_get_header_field(&req.hdr, "If-None-Match");
            if ((if_none_match != NULL && strstr(if_none_match, uri.meta->etag) == NULL) ||
                (accept_if_modified_since && if_modified_since != NULL && strcmp(if_modified_since, last_modified) == 0))
            {
                res.status = http_get_status(304);
                goto respond;
            }

            const char *range = http_get_header_field(&req.hdr, "Range");
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

            if (file == NULL) {
                file = fopen(uri.filename, "rb");
            }

            fseek(file, 0, SEEK_END);
            content_length = ftell(file);
            fseek(file, 0, SEEK_SET);
        } else {
            int mode;
            if (strcmp(uri.filename + strlen(uri.filename) - 4, ".ncr") == 0) {
                mode = FASTCGI_SESIMOS;
            } else if (strcmp(uri.filename + strlen(uri.filename) - 4, ".php") == 0) {
                mode = FASTCGI_PHP;
            } else {
                res.status = http_get_status(500);
                print(ERR_STR "Invalid FastCGI extension: %s" CLR_STR, uri.filename);
                goto respond;
            }

            struct stat statbuf;
            stat(uri.filename, &statbuf);
            char *last_modified = http_format_date(statbuf.st_mtime, buf0, sizeof(buf0));
            http_add_header_field(&res.hdr, "Last-Modified", last_modified);

            res.status = http_get_status(200);
            if (fastcgi_init(&fcgi_conn, mode, client_num, req_num, client, &req, &uri) != 0) {
                res.status = http_get_status(503);
                sprintf(err_msg, "Unable to communicate with FastCGI socket.");
                goto respond;
            }

            const char *client_content_length = http_get_header_field(&req.hdr, "Content-Length");
            if (client_content_length != NULL) {
                unsigned long client_content_len = strtoul(client_content_length, NULL, 10);
                ret = fastcgi_receive(&fcgi_conn, client, client_content_len);
                if (ret != 0) {
                    if (ret < 0) {
                        goto abort;
                    } else {
                        sprintf(err_msg, "Unable to communicate with FastCGI socket.");
                    }
                    res.status = http_get_status(502);
                    goto respond;
                }
            }
            fastcgi_close_stdin(&fcgi_conn);

            ret = fastcgi_header(&fcgi_conn, &res, err_msg);
            if (ret != 0) {
                if (ret < 0) goto abort;
                goto respond;
            }

            const char *status = http_get_header_field(&res.hdr, "Status");
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

            const char *content_length_f = http_get_header_field(&res.hdr, "Content-Length");
            content_length = (content_length_f == NULL) ? -1 : strtol(content_length_f, NULL, 10);

            const char *content_type = http_get_header_field(&res.hdr, "Content-Type");
            const char *content_encoding = http_get_header_field(&res.hdr, "Content-Encoding");
            if (content_encoding == NULL &&
                content_type != NULL &&
                strncmp(content_type, "text/html", 9) == 0 &&
                content_length != -1 &&
                content_length <= sizeof(msg_content) - 1)
            {
                fastcgi_dump(&fcgi_conn, msg_content, sizeof(msg_content));
                goto respond;
            }

            use_fastcgi = 1;

            if (content_length != -1 && content_length < 1024000) {
                use_fastcgi |= FASTCGI_COMPRESS_HOLD;
            }

            content_length = -1;

            int http_comp = http_get_compression(&req, &res);
            if (http_comp & COMPRESS) {
                if (http_comp & COMPRESS_BR) {
                    use_fastcgi |= FASTCGI_COMPRESS_BR;
                    sprintf(buf0, "br");
                } else if (http_comp & COMPRESS_GZ) {
                    use_fastcgi |= FASTCGI_COMPRESS_GZ;
                    sprintf(buf0, "gzip");
                }
                http_add_header_field(&res.hdr, "Vary", "Accept-Encoding");
                http_add_header_field(&res.hdr, "Content-Encoding", buf0);
                http_remove_header_field(&res.hdr, "Content-Length", HTTP_REMOVE_ALL);
            }

            if (http_get_header_field(&res.hdr, "Content-Length") == NULL) {
                http_add_header_field(&res.hdr, "Transfer-Encoding", "chunked");
            }
        }
    } else if (conf->type == CONFIG_TYPE_REVERSE_PROXY) {
        print("Reverse proxy for " BLD_STR "%s:%i" CLR_STR, conf->rev_proxy.hostname, conf->rev_proxy.port);
        http_remove_header_field(&res.hdr, "Date", HTTP_REMOVE_ALL);
        http_remove_header_field(&res.hdr, "Server", HTTP_REMOVE_ALL);

        ret = rev_proxy_init(&req, &res, &ctx, conf, client, &custom_status, err_msg);
        use_rev_proxy = (ret == 0);

        if (res.status->code == 101) {
            const char *connection = http_get_header_field(&res.hdr, "Connection");
            const char *upgrade = http_get_header_field(&res.hdr, "Upgrade");
            if (connection != NULL && upgrade != NULL &&
                (strstr(connection, "upgrade") != NULL || strstr(connection, "Upgrade") != NULL) &&
                strcmp(upgrade, "websocket") == 0)
            {
                const char *ws_accept = http_get_header_field(&res.hdr, "Sec-WebSocket-Accept");
                if (ws_calc_accept_key(ctx.ws_key, buf0) == 0) {
                    use_rev_proxy = (strcmp(buf0, ws_accept) == 0) ? 2 : 1;
                }
            } else {
                print("Fail Test1");
                ctx.status = 101;
                ctx.origin = INTERNAL;
                res.status = http_get_status(501);
            }
        }

        // Let 300 be formatted by origin server
        if (use_rev_proxy && res.status->code >= 301 && res.status->code < 600) {
            const char *content_type = http_get_header_field(&res.hdr, "Content-Type");
            const char *content_length_f = http_get_header_field(&res.hdr, "Content-Length");
            const char *content_encoding = http_get_header_field(&res.hdr, "Content-Encoding");
            if (content_encoding == NULL && content_type != NULL && content_length_f != NULL && strncmp(content_type, "text/html", 9) == 0) {
                long content_len = strtol(content_length_f, NULL, 10);
                if (content_len <= sizeof(msg_content) - 1) {
                    if (ctx.status != 101) {
                        ctx.status = res.status->code;
                        ctx.origin = res.status->code >= 400 ? SERVER : NONE;
                    }
                    use_rev_proxy = 0;
                    rev_proxy_dump(msg_content, content_len);
                }
            }
        }

        /*
        char *content_encoding = http_get_header_field(&res.hdr, "Content-Encoding");
        if (use_rev_proxy && content_encoding == NULL) {
            int http_comp = http_get_compression(&req, &res);
            if (http_comp & COMPRESS_BR) {
                use_rev_proxy |= REV_PROXY_COMPRESS_BR;
            } else if (http_comp & COMPRESS_GZ) {
                use_rev_proxy |= REV_PROXY_COMPRESS_GZ;
            }
        }

        char *transfer_encoding = http_get_header_field(&res.hdr, "Transfer-Encoding");
        int chunked = transfer_encoding != NULL && strcmp(transfer_encoding, "chunked") == 0;
        http_remove_header_field(&res.hdr, "Transfer-Encoding", HTTP_REMOVE_ALL);
        ret = sprintf(buf0, "%s%s%s",
                      (use_rev_proxy & REV_PROXY_COMPRESS_BR) ? "br" :
                      ((use_rev_proxy & REV_PROXY_COMPRESS_GZ) ? "gzip" : ""),
                      ((use_rev_proxy & REV_PROXY_COMPRESS) && chunked) ? ", " : "",
                      chunked ? "chunked" : "");
        if (ret > 0) {
            http_add_header_field(&res.hdr, "Transfer-Encoding", buf0);
        }
        */
    } else {
        print(ERR_STR "Unknown host type: %i" CLR_STR, conf->type);
        res.status = http_get_status(501);
    }

    respond:
    if (!use_rev_proxy) {
        if (conf != NULL && conf->type == CONFIG_TYPE_LOCAL && uri.is_static && res.status->code == 405) {
            http_add_header_field(&res.hdr, "Allow", "GET, HEAD, TRACE");
        }
        if (http_get_header_field(&res.hdr, "Accept-Ranges") == NULL) {
            http_add_header_field(&res.hdr, "Accept-Ranges", "none");
        }
        if (!use_fastcgi && file == NULL) {
            http_remove_header_field(&res.hdr, "Date", HTTP_REMOVE_ALL);
            http_remove_header_field(&res.hdr, "Server", HTTP_REMOVE_ALL);
            http_remove_header_field(&res.hdr, "Cache-Control", HTTP_REMOVE_ALL);
            http_remove_header_field(&res.hdr, "Content-Type", HTTP_REMOVE_ALL);
            http_remove_header_field(&res.hdr, "Content-Encoding", HTTP_REMOVE_ALL);
            http_add_header_field(&res.hdr, "Date", http_get_date(buf0, sizeof(buf0)));
            http_add_header_field(&res.hdr, "Server", SERVER_STR);
            http_add_header_field(&res.hdr, "Cache-Control", "no-cache");
            http_add_header_field(&res.hdr, "Content-Type", "text/html; charset=UTF-8");

            // TODO list Locations on 3xx Redirects
            const http_doc_info *info = http_get_status_info(res.status);
            const http_status_msg *http_msg = http_get_error_msg(res.status);

            if (msg_content[0] == 0) {
                if (res.status->code >= 300 && res.status->code < 400) {
                    const char *location = http_get_header_field(&res.hdr, "Location");
                    if (location != NULL) {
                        snprintf(msg_content, sizeof(msg_content), "<ul>\n\t<li><a href=\"%1$s\">%1$s</a></li>\n</ul>\n", location);
                    }
                }
            } else if (strncmp(msg_content, "<!DOCTYPE html>", 15) == 0 || strncmp(msg_content, "<html", 5) == 0) {
                msg_content[0] = 0;
                // TODO let relevant information pass?
            }

            char *rev_proxy_doc = "";
            if (conf != NULL && conf->type == CONFIG_TYPE_REVERSE_PROXY) {
                const http_status *status = http_get_status(ctx.status);
                char stat_str[8];
                sprintf(stat_str, "%03i", ctx.status);
                sprintf(msg_pre_buf_2, http_rev_proxy_document,
                        " success",
                        (ctx.origin == CLIENT_REQ) ? " error" : " success",
                        (ctx.origin == INTERNAL) ? " error" : " success",
                        (ctx.origin == SERVER_REQ) ? " error" : (ctx.status == 0 ? "" : " success"),
                        (ctx.origin == CLIENT_RES) ? " error" : " success",
                        (ctx.origin == SERVER) ? " error" : (ctx.status == 0 ? "" : " success"),
                        (ctx.origin == SERVER_RES) ? " error" : (ctx.status == 0 ? "" : " success"),
                        (ctx.origin == INTERNAL) ? " error" : " success",
                        (ctx.origin == INTERNAL || ctx.origin == SERVER) ? " error" : " success",
                        res.status->code,
                        res.status->msg,
                        (ctx.status == 0) ? "???" : stat_str,
                        (status != NULL) ? status->msg : "",
                        host);
                rev_proxy_doc = msg_pre_buf_2;
            }

            sprintf(msg_pre_buf_1, info->doc, res.status->code, res.status->msg, http_msg != NULL ? http_msg->msg : "", err_msg[0] != 0 ? err_msg : "");
            content_length = snprintf(msg_buf, sizeof(msg_buf), http_default_document, res.status->code,
                                      res.status->msg, msg_pre_buf_1, info->mode, info->icon, info->color, host,
                                      rev_proxy_doc, msg_content[0] != 0 ? msg_content : "");
        }
        if (content_length >= 0) {
            sprintf(buf0, "%li", content_length);
            http_remove_header_field(&res.hdr, "Content-Length", HTTP_REMOVE_ALL);
            http_add_header_field(&res.hdr, "Content-Length", buf0);
        } else if (http_get_header_field(&res.hdr, "Transfer-Encoding") == NULL) {
            server_keep_alive = 0;
        }
    }

    int close_proxy = 0;
    if (use_rev_proxy != 2) {
        const char *conn = http_get_header_field(&res.hdr, "Connection");
        close_proxy = (conn == NULL || (strstr(conn, "keep-alive") == NULL && strstr(conn, "Keep-Alive") == NULL));
        http_remove_header_field(&res.hdr, "Connection", HTTP_REMOVE_ALL);
        http_remove_header_field(&res.hdr, "Keep-Alive", HTTP_REMOVE_ALL);
        if (server_keep_alive && client_keep_alive) {
            http_add_header_field(&res.hdr, "Connection", "keep-alive");
            sprintf(buf0, "timeout=%i, max=%i", CLIENT_TIMEOUT, REQ_PER_CONNECTION);
            http_add_header_field(&res.hdr, "Keep-Alive", buf0);
        } else {
            http_add_header_field(&res.hdr, "Connection", "close");
        }
    }

    http_send_response(client, &res);
    clock_gettime(CLOCK_MONOTONIC, &end);
    const char *location = http_get_header_field(&res.hdr, "Location");
    unsigned long micros = (end.tv_nsec - begin.tv_nsec) / 1000 + (end.tv_sec - begin.tv_sec) * 1000000;
    print("%s%s%03i %s%s%s (%s)%s", http_get_status_color(res.status), use_rev_proxy ? "-> " : "", res.status->code,
          res.status->msg, location != NULL ? " -> " : "", location != NULL ? location : "",
          format_duration(micros, buf0), CLR_STR);

    // TODO access/error log file

    if (use_rev_proxy == 2) {
        // WebSocket
        print("Upgrading connection to WebSocket connection");
        ret = ws_handle_connection(client, &rev_proxy);
        if (ret != 0) {
            client_keep_alive = 0;
            close_proxy = 1;
        }
        print("WebSocket connection closed");
    } else if (strcmp(req.method, "HEAD") != 0) {
        // default response
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
                ret = sock_send(client, buffer, len, feof(file) ? 0 : MSG_MORE);
                if (ret <= 0) {
                    print(ERR_STR "Unable to send: %s" CLR_STR, sock_strerror(client));
                    break;
                }
                snd_len += ret;
            }
        } else if (use_fastcgi) {
            const char *transfer_encoding = http_get_header_field(&res.hdr, "Transfer-Encoding");
            int chunked = (transfer_encoding != NULL && strcmp(transfer_encoding, "chunked") == 0);

            int flags = (chunked ? FASTCGI_CHUNKED : 0) | (use_fastcgi & (FASTCGI_COMPRESS | FASTCGI_COMPRESS_HOLD));
            ret = fastcgi_send(&fcgi_conn, client, flags);
        } else if (use_rev_proxy) {
            const char *transfer_encoding = http_get_header_field(&res.hdr, "Transfer-Encoding");
            int chunked = transfer_encoding != NULL && strstr(transfer_encoding, "chunked") != NULL;

            const char *content_len = http_get_header_field(&res.hdr, "Content-Length");
            unsigned long len_to_send = 0;
            if (content_len != NULL) {
                len_to_send = strtol(content_len, NULL, 10);
            }

            int flags = (chunked ? REV_PROXY_CHUNKED : 0) | (use_rev_proxy & REV_PROXY_COMPRESS);
            ret = rev_proxy_send(client, len_to_send, flags);
        }

        if (ret < 0) {
            client_keep_alive = 0;
        }
    }

    if (close_proxy && rev_proxy.socket != 0) {
        print(BLUE_STR "Closing proxy connection" CLR_STR);
        sock_close(&rev_proxy);
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    micros = (end.tv_nsec - begin.tv_nsec) / 1000 + (end.tv_sec - begin.tv_sec) * 1000000;
    print("Transfer complete: %s", format_duration(micros, buf0));

    uri_free(&uri);
    abort:
    if (fcgi_conn.socket != 0) {
        shutdown(fcgi_conn.socket, SHUT_RDWR);
        close(fcgi_conn.socket);
        fcgi_conn.socket = 0;
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
            snprintf(client_cc, sizeof(client_cc), "%s", pos);
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
            ret = -1;
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
            ntohs(server_addr->sin6_port), CLR_STR, color_table[client_num % 6], INET6_ADDRSTRLEN, client_addr_str,
            ntohs(client_addr->sin6_port), CLR_STR);

    log_conn_prefix = malloc(256);
    sprintf(log_conn_prefix, "[%6i][%*s]%s ", getpid(), INET6_ADDRSTRLEN, server_addr_str, log_client_prefix);
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
