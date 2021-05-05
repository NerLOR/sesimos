/**
 * Necronda Web Server
 * Reverse proxy
 * src/lib/rev_proxy.c
 * Lorenz Stechauner, 2021-01-07
 */

#include "rev_proxy.h"
#include "utils.h"
#include "compress.h"
#include "../necronda-server.h"
#include <openssl/ssl.h>
#include <string.h>
#include <errno.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/time.h>

sock rev_proxy;
char *rev_proxy_host = NULL;
struct timeval server_timeout = {.tv_sec = SERVER_TIMEOUT, .tv_usec = 0};

int rev_proxy_preload() {
    rev_proxy.buf = NULL;
    rev_proxy.buf_len = 0;
    rev_proxy.buf_off = 0;
    rev_proxy.ctx = SSL_CTX_new(TLS_client_method());
    return 0;
}

int rev_proxy_request_header(http_req *req, int enc) {
    char buf1[256];
    char buf2[256];
    int p_len;
    http_remove_header_field(&req->hdr, "Connection", HTTP_REMOVE_ALL);
    http_add_header_field(&req->hdr, "Connection", "keep-alive");

    char *via = http_get_header_field(&req->hdr, "Via");
    sprintf(buf1, "HTTP/%s %s", req->version, DEFAULT_HOST);
    if (via == NULL) {
        http_add_header_field(&req->hdr, "Via", buf1);
    } else {
        p_len = snprintf(buf2, sizeof(buf2), "%s, %s", via, buf1);
        if (p_len < 0 || p_len >= sizeof(buf2)) {
            print(ERR_STR "Header field 'Via' too long" CLR_STR);
            return -1;
        }
        http_remove_header_field(&req->hdr, "Via", HTTP_REMOVE_ALL);
        http_add_header_field(&req->hdr, "Via", buf2);
    }

    char *host = http_get_header_field(&req->hdr, "Host");
    char *forwarded = http_get_header_field(&req->hdr, "Forwarded");
    int client_ipv6 = strchr(client_addr_str, ':') != NULL;
    int server_ipv6 =  strchr(server_addr_str, ':') != NULL;

    p_len = snprintf(buf1, sizeof(buf1), "by=%s%s%s;for=%s%s%s;host=%s;proto=%s",
                     server_ipv6 ? "\"[" : "", server_addr_str, server_ipv6 ? "]\"" : "",
                     client_ipv6 ? "\"[" : "", client_addr_str, client_ipv6 ? "]\"" : "",
                     host, enc ? "https" : "http");
    if (p_len < 0 || p_len >= sizeof(buf1)) {
        print(ERR_STR "Appended part of header field 'Forwarded' too long" CLR_STR);
        return -1;
    }
    if (forwarded == NULL) {
        http_add_header_field(&req->hdr, "Forwarded", buf1);
    } else {
        p_len = snprintf(buf2, sizeof(buf2), "%s, %s", forwarded, buf1);
        if (p_len < 0 || p_len >= sizeof(buf2)) {
            print(ERR_STR "Header field 'Forwarded' too long" CLR_STR);
            return -1;
        }
        http_remove_header_field(&req->hdr, "Forwarded", HTTP_REMOVE_ALL);
        http_add_header_field(&req->hdr, "Forwarded", buf2);
    }

    char *xff = http_get_header_field(&req->hdr, "X-Forwarded-For");
    if (xff == NULL) {
        http_add_header_field(&req->hdr, "X-Forwarded-For", client_addr_str);
    } else {
        sprintf(buf1, "%s, %s", xff, client_addr_str);
        http_remove_header_field(&req->hdr, "X-Forwarded-For", HTTP_REMOVE_ALL);
        http_add_header_field(&req->hdr, "X-Forwarded-For", buf1);
    }

    char *xfh = http_get_header_field(&req->hdr, "X-Forwarded-Host");
    if (xfh == NULL) {
        if (forwarded == NULL) {
            http_add_header_field(&req->hdr, "X-Forwarded-Host", host);
        } else {
            char *ptr = strchr(forwarded, ',');
            unsigned long len;
            if (ptr != NULL) len = ptr - forwarded;
            else len = strlen(forwarded);
            ptr = strstr(forwarded, "host=");
            if ((ptr - forwarded) < len) {
                char *end = strchr(ptr, ';');
                if (end == NULL) len -= (ptr - forwarded);
                else len = (end - ptr);
                len -= 5;
                sprintf(buf1, "%.*s", (int) len, ptr + 5);
                http_add_header_field(&req->hdr, "X-Forwarded-Host", buf1);
            }
        }
    }

    char *xfp = http_get_header_field(&req->hdr, "X-Forwarded-Proto");
    if (xfp == NULL) {
        if (forwarded == NULL) {
            http_add_header_field(&req->hdr, "X-Forwarded-Proto", enc ? "https" : "http");
        } else {
            char *ptr = strchr(forwarded, ',');
            unsigned long len;
            if (ptr != NULL) len = ptr - forwarded;
            else len = strlen(forwarded);
            ptr = strstr(forwarded, "proto=");
            if ((ptr - forwarded) < len) {
                char *end = strchr(ptr, ';');
                if (end == NULL) len -= (ptr - forwarded);
                else len = (end - ptr);
                len -= 6;
                sprintf(buf1, "%.*s", (int) len, ptr + 6);
                http_add_header_field(&req->hdr, "X-Forwarded-Proto", buf1);
            }
        }
    }

    return 0;
}

int rev_proxy_response_header(http_req *req, http_res *res) {
    char buf1[256];
    char buf2[256];
    int p_len;

    char *via = http_get_header_field(&res->hdr, "Via");
    p_len = snprintf(buf1, sizeof(buf1), "HTTP/%s %s", req->version, DEFAULT_HOST);
    if (p_len < 0 || p_len >= sizeof(buf1)) {
        print(ERR_STR "Appended part of header field 'Via' too long" CLR_STR);
        return -1;
    }
    if (via == NULL) {
        http_add_header_field(&res->hdr, "Via", buf1);
    } else {
        p_len = snprintf(buf2, sizeof(buf2), "%s, %s", via, buf1);
        if (p_len < 0 || p_len >= sizeof(buf2)) {
            print(ERR_STR "Header field 'Via' too long" CLR_STR);
            return -1;
        }
        http_remove_header_field(&res->hdr, "Via", HTTP_REMOVE_ALL);
        http_add_header_field(&res->hdr, "Via", buf2);
    }

    return 0;
}

int rev_proxy_init(http_req *req, http_res *res, host_config *conf, sock *client, http_status *custom_status,
                   char *err_msg) {
    char buffer[CHUNK_SIZE];
    long ret;
    int tries = 0;
    int retry = 0;

    if (rev_proxy.socket != 0 && strcmp(rev_proxy_host, conf->name) == 0 && sock_check(&rev_proxy) == 0) {
        goto rev_proxy;
    }

    retry:
    if (rev_proxy.socket != 0) {
        print(BLUE_STR "Closing proxy connection" CLR_STR);
        sock_close(&rev_proxy);
    }
    retry = 0;
    tries++;

    rev_proxy.socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (rev_proxy.socket  < 0) {
        print(ERR_STR "Unable to create socket: %s" CLR_STR, strerror(errno));
        res->status = http_get_status(500);
        return -1;
    }

    server_timeout.tv_sec = SERVER_TIMEOUT;
    server_timeout.tv_usec = 0;
    if (setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, &server_timeout, sizeof(server_timeout)) < 0)
        goto rev_proxy_timeout_err;
    if (setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, &server_timeout, sizeof(server_timeout)) < 0) {
        rev_proxy_timeout_err:
        res->status = http_get_status(502);
        print(ERR_STR "Unable to set timeout for socket: %s" CLR_STR, strerror(errno));
        sprintf(err_msg, "Unable to set timeout for socket: %s", strerror(errno));
        goto proxy_err;
    }

    struct hostent *host_ent = gethostbyname(conf->rev_proxy.hostname);
    if (host_ent == NULL) {
        res->status = http_get_status(502);
        print(ERR_STR "Unable to connect to server: Name or service not known" CLR_STR);
        sprintf(err_msg, "Unable to connect to server: Name or service not known.");
        goto proxy_err;
    }

    struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = htons(conf->rev_proxy.port)};
    if (host_ent->h_addrtype == AF_INET6) {
        memcpy(&address.sin6_addr, host_ent->h_addr_list[0], host_ent->h_length);
    } else if (host_ent->h_addrtype == AF_INET) {
        unsigned char addr[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0};
        memcpy(addr + 12, host_ent->h_addr_list[0], host_ent->h_length);
        memcpy(&address.sin6_addr, addr, 16);
    }

    if (connect(rev_proxy.socket, (struct sockaddr *) &address, sizeof(address)) < 0) {
        res->status = http_get_status(502);
        print(ERR_STR "Unable to connect to server: %s" CLR_STR, strerror(errno));
        sprintf(err_msg, "Unable to connect to server: %s.", strerror(errno));
        goto proxy_err;
    }

    if (conf->rev_proxy.enc) {
        rev_proxy.ssl = SSL_new(rev_proxy.ctx);
        SSL_set_fd(rev_proxy.ssl, rev_proxy.socket);
        SSL_set_connect_state(rev_proxy.ssl);

        ret = SSL_do_handshake(rev_proxy.ssl);
        rev_proxy._last_ret = ret;
        rev_proxy._errno = errno;
        rev_proxy._ssl_error = ERR_get_error();
        rev_proxy.enc = 1;
        if (ret < 0) {
            res->status = http_get_status(502);
            print(ERR_STR "Unable to perform handshake: %s" CLR_STR, sock_strerror(&rev_proxy));
            sprintf(err_msg, "Unable to perform handshake: %s.", sock_strerror(&rev_proxy));
            goto proxy_err;
        }
    }

    rev_proxy_host = conf->name;
    inet_ntop(address.sin6_family, (void *) &address.sin6_addr, buffer, sizeof(buffer));
    print(BLUE_STR "Established new connection with " BLD_STR "[%s]:%i" CLR_STR, buffer, conf->rev_proxy.port);

    rev_proxy:
    ret = rev_proxy_request_header(req, (int) client->enc);
    if (ret != 0) {
        res->status = http_get_status(500);
        return -1;
    }

    ret = http_send_request(&rev_proxy, req);
    if (ret < 0) {
        res->status = http_get_status(502);
        print(ERR_STR "Unable to send request to server (1): %s" CLR_STR, sock_strerror(&rev_proxy));
        sprintf(err_msg, "Unable to send request to server: %s.", sock_strerror(&rev_proxy));
        retry = tries < 4;
        goto proxy_err;
    }

    char *content_length = http_get_header_field(&req->hdr, "Content-Length");
    if (content_length != NULL) {
        unsigned long content_len = strtoul(content_length, NULL, 10);
        if (client->buf_len - client->buf_off > 0) {
            unsigned long len = client->buf_len - client->buf_off;
            if (len > content_len) {
                len = content_len;
            }
            ret = sock_send(&rev_proxy, client->buf, len, 0);
            if (ret <= 0) {
                res->status = http_get_status(502);
                print(ERR_STR "Unable to send request to server (2): %s" CLR_STR, sock_strerror(&rev_proxy));
                sprintf(err_msg, "Unable to send request to server: %s.", sock_strerror(&rev_proxy));
                retry = tries < 4;
                goto proxy_err;
            }
            content_len -= len;
        }
        if (content_len > 0) {
            ret = sock_splice(&rev_proxy, client, buffer, sizeof(buffer), content_len);
            if (ret <= 0) {
                if (ret == -1) {
                    res->status = http_get_status(502);
                    print(ERR_STR "Unable to send request to server (3): %s" CLR_STR, sock_strerror(&rev_proxy));
                    sprintf(err_msg, "Unable to send request to server: %s.", sock_strerror(&rev_proxy));
                    goto proxy_err;
                } else if (ret == -2) {
                    res->status = http_get_status(400);
                    print(ERR_STR "Unable to receive request from client: %s" CLR_STR, sock_strerror(client));
                    sprintf(err_msg, "Unable to receive request from client: %s.", sock_strerror(client));
                    return -1;
                }
                res->status = http_get_status(500);
                print(ERR_STR "Unknown Error" CLR_STR);
                return -1;
            }
        }
    }

    ret = sock_recv(&rev_proxy, buffer, sizeof(buffer), MSG_PEEK);
    if (ret <= 0) {
        res->status = http_get_status(502);
        print(ERR_STR "Unable to receive response from server: %s" CLR_STR, sock_strerror(&rev_proxy));
        sprintf(err_msg, "Unable to receive response from server: %s.", sock_strerror(&rev_proxy));
        goto proxy_err;
    }

    char *buf = buffer;
    unsigned short header_len = (unsigned short) (strstr(buffer, "\r\n\r\n") - buffer + 4);

    if (header_len <= 0) {
        res->status = http_get_status(502);
        print(ERR_STR "Unable to parse header: End of header not found" CLR_STR);
        sprintf(err_msg, "Unable to parser header: End of header not found.");
        goto proxy_err;
    }

    for (int i = 0; i < header_len; i++) {
        if ((buf[i] >= 0x00 && buf[i] <= 0x1F && buf[i] != '\r' && buf[i] != '\n') || buf[i] == 0x7F) {
            res->status = http_get_status(502);
            print(ERR_STR "Unable to parse header: Header contains illegal characters" CLR_STR);
            sprintf(err_msg, "Unable to parse header: Header contains illegal characters.");
            goto proxy_err;
        }
    }

    char *ptr = buf;
    while (header_len != (ptr - buf)) {
        char *pos0 = strstr(ptr, "\r\n");
        if (pos0 == NULL) {
            res->status = http_get_status(502);
            print(ERR_STR "Unable to parse header: Invalid header format" CLR_STR);
            sprintf(err_msg, "Unable to parse header: Invalid header format.");
            goto proxy_err;
        }
        if (ptr == buf) {
            if (strncmp(ptr, "HTTP/", 5) != 0) {
                res->status = http_get_status(502);
                print(ERR_STR "Unable to parse header: Invalid header format" CLR_STR);
                sprintf(err_msg, "Unable to parse header: Invalid header format.");
                goto proxy_err;
            }
            int status_code = (int) strtol(ptr + 9, NULL, 10);
            res->status = http_get_status(status_code);
            if (res->status == NULL && status_code >= 100 && status_code <= 999) {
                custom_status->code = status_code;
                strcpy(custom_status->type, "");
                strncpy(custom_status->msg, ptr + 13, strchr(ptr, '\r') - ptr - 13);
                res->status = custom_status;
            } else if (res->status == NULL) {
                res->status = http_get_status(502);
                print(ERR_STR "Unable to parse header: Invalid or unknown status code" CLR_STR);
                sprintf(err_msg, "Unable to parse header: Invalid or unknown status code.");
                goto proxy_err;
            }
        } else {
            ret = http_parse_header_field(&res->hdr, ptr, pos0);
            if (ret != 0) {
                res->status = http_get_status(502);
                print(ERR_STR "Unable to parse header" CLR_STR);
                sprintf(err_msg, "Unable to parse header.");
                goto proxy_err;
            }
        }
        if (pos0[2] == '\r' && pos0[3] == '\n') {
            break;
        }
        ptr = pos0 + 2;
    }
    sock_recv(&rev_proxy, buffer, header_len, 0);

    ret = rev_proxy_response_header(req, res);
    if (ret != 0) {
        res->status = http_get_status(500);
        return -1;
    }

    return 0;

    proxy_err:
    if (retry) goto retry;
    return -1;
}

int rev_proxy_send(sock *client, unsigned long len_to_send, int flags) {
    // TODO handle websockets
    long ret;
    char buffer[CHUNK_SIZE];
    char comp_out[CHUNK_SIZE];
    char buf[256];
    long len, snd_len;
    int finish_comp = 0;
    char *ptr;

    compress_ctx comp_ctx;
    if (flags & REV_PROXY_COMPRESS_BR) {
        flags &= ~REV_PROXY_COMPRESS_GZ;
        if (compress_init(&comp_ctx, COMPRESS_BR) != 0) {
            print(ERR_STR "Unable to init brotli: %s" CLR_STR, strerror(errno));
            flags &= ~REV_PROXY_COMPRESS_BR;
        }
    } else if (flags & REV_PROXY_COMPRESS_GZ) {
        flags &= ~REV_PROXY_COMPRESS_BR;
        if (compress_init(&comp_ctx, COMPRESS_GZ) != 0) {
            print(ERR_STR "Unable to init gzip: %s" CLR_STR, strerror(errno));
            flags &= ~REV_PROXY_COMPRESS_GZ;
        }
    }

    do {
        if (flags & REV_PROXY_CHUNKED) {
            ret = sock_recv(&rev_proxy, buffer, 16, MSG_PEEK);
            if (ret <= 0) {
                print("Unable to receive: %s", sock_strerror(&rev_proxy));
                break;
            }

            len_to_send = strtol(buffer, NULL, 16);
            char *pos = strstr(buffer, "\r\n");
            len = pos - buffer + 2;
            sock_recv(&rev_proxy, buffer, len, 0);
            if (ret <= 0) break;

            if (len_to_send == 0 && (flags & REV_PROXY_COMPRESS)) {
                finish_comp = 1;
                len = 0;
                goto out;
                finish:
                compress_free(&comp_ctx);
            }
        }
        snd_len = 0;
        while (snd_len < len_to_send) {
            unsigned long avail_in, avail_out;
            len = sock_recv(&rev_proxy, buffer, CHUNK_SIZE < (len_to_send - snd_len) ? CHUNK_SIZE : len_to_send - snd_len, 0);
            ptr = buffer;
            out:
            avail_in = len;
            void *next_in = ptr;
            do {
                long buf_len = len;
                if (flags & REV_PROXY_COMPRESS) {
                    avail_out = sizeof(comp_out);
                    compress_compress(&comp_ctx, next_in + len - avail_in, &avail_in, comp_out, &avail_out,
                                      finish_comp);
                    ptr = comp_out;
                    buf_len = (int) (sizeof(comp_out) - avail_out);
                    snd_len += (long) (len - avail_in);
                }
                if (buf_len != 0) {
                    len = sprintf(buf, "%lX\r\n", buf_len);
                    ret = 1;
                    if (flags & REV_PROXY_CHUNKED) ret = sock_send(client, buf, len, 0);
                    if (ret <= 0) goto err;
                    ret = sock_send(client, ptr, buf_len, 0);
                    if (ret <= 0) goto err;
                    if (!(flags & REV_PROXY_COMPRESS)) snd_len += ret;
                    if (flags & REV_PROXY_CHUNKED) ret = sock_send(client, "\r\n", 2, 0);
                    if (ret <= 0) {
                        err:
                        print(ERR_STR "Unable to send: %s" CLR_STR, sock_strerror(client));
                        break;
                    }
                }
            } while ((flags & REV_PROXY_COMPRESS) && (avail_in != 0 || avail_out != sizeof(comp_out)));
            if (ret <= 0) break;
            if (finish_comp) goto finish;
        }
        if (ret <= 0) break;
        if (flags & REV_PROXY_CHUNKED) sock_recv(&rev_proxy, buffer, 2, 0);
    } while ((flags & REV_PROXY_CHUNKED) && len_to_send > 0);

    if (flags & REV_PROXY_CHUNKED) {
        sock_send(client, "0\r\n\r\n", 5, 0);
    }

    return 0;
}
