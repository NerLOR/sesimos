/**
 * sesimos - secure, simple, modern web server
 * @brief Reverse proxy
 * @file src/lib/proxy.c
 * @author Lorenz Stechauner
 * @date 2021-01-07
 */

#include "../defs.h"
#include "../server.h"
#include "../logger.h"
#include "proxy.h"
#include "utils.h"
#include "compress.h"

#include <openssl/ssl.h>
#include <string.h>
#include <errno.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <sys/time.h>


sock proxy;
char *proxy_host = NULL;
struct timeval server_timeout = {.tv_sec = SERVER_TIMEOUT, .tv_usec = 0};

int proxy_preload(void) {
    proxy.ctx = SSL_CTX_new(TLS_client_method());
    return 0;
}

int proxy_request_header(http_req *req, int enc, client_ctx_t *ctx) {
    char buf1[256], buf2[256];
    int p_len;

    const char *via = http_get_header_field(&req->hdr, "Via");
    sprintf(buf1, "HTTP/%s %s", req->version, SERVER_NAME);
    if (via == NULL) {
        http_add_header_field(&req->hdr, "Via", buf1);
    } else {
        p_len = snprintf(buf2, sizeof(buf2), "%s, %s", via, buf1);
        if (p_len < 0 || p_len >= sizeof(buf2)) {
            error("Header field 'Via' too long");
            return -1;
        }
        http_remove_header_field(&req->hdr, "Via", HTTP_REMOVE_ALL);
        http_add_header_field(&req->hdr, "Via", buf2);
    }

    const char *host = http_get_header_field(&req->hdr, "Host");
    const char *forwarded = http_get_header_field(&req->hdr, "Forwarded");
    int client_ipv6 = strchr(ctx->addr, ':') != NULL;
    int server_ipv6 = strchr(ctx->s_addr, ':') != NULL;

    p_len = snprintf(buf1, sizeof(buf1), "by=%s%s%s;for=%s%s%s;host=%s;proto=%s",
                     server_ipv6 ? "\"[" : "", ctx->s_addr, server_ipv6 ? "]\"" : "",
                     client_ipv6 ? "\"[" : "", ctx->addr, client_ipv6 ? "]\"" : "",
                     host, enc ? "https" : "http");
    if (p_len < 0 || p_len >= sizeof(buf1)) {
        error("Appended part of header field 'Forwarded' too long");
        return -1;
    }

    if (forwarded == NULL) {
        http_add_header_field(&req->hdr, "Forwarded", buf1);
    } else {
        p_len = snprintf(buf2, sizeof(buf2), "%s, %s", forwarded, buf1);
        if (p_len < 0 || p_len >= sizeof(buf2)) {
            error("Header field 'Forwarded' too long");
            return -1;
        }
        http_remove_header_field(&req->hdr, "Forwarded", HTTP_REMOVE_ALL);
        http_add_header_field(&req->hdr, "Forwarded", buf2);
    }

    const char *xff = http_get_header_field(&req->hdr, "X-Forwarded-For");
    if (xff == NULL) {
        http_add_header_field(&req->hdr, "X-Forwarded-For", ctx->addr);
    } else {
        sprintf(buf1, "%s, %s", xff, ctx->addr);
        http_remove_header_field(&req->hdr, "X-Forwarded-For", HTTP_REMOVE_ALL);
        http_add_header_field(&req->hdr, "X-Forwarded-For", buf1);
    }

    const char *xfh = http_get_header_field(&req->hdr, "X-Forwarded-Host");
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

    const char *xfp = http_get_header_field(&req->hdr, "X-Forwarded-Proto");
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

int proxy_response_header(http_req *req, http_res *res, host_config_t *conf) {
    char buf1[256], buf2[256];
    int p_len;

    const char *via = http_get_header_field(&res->hdr, "Via");
    p_len = snprintf(buf1, sizeof(buf1), "HTTP/%s %s", req->version, SERVER_NAME);
    if (p_len < 0 || p_len >= sizeof(buf1)) {
        error("Appended part of header field 'Via' too long");
        return -1;
    }
    if (via == NULL) {
        http_add_header_field(&res->hdr, "Via", buf1);
    } else {
        p_len = snprintf(buf2, sizeof(buf2), "%s, %s", via, buf1);
        if (p_len < 0 || p_len >= sizeof(buf2)) {
            error("Header field 'Via' too long");
            return -1;
        }
        http_remove_header_field(&res->hdr, "Via", HTTP_REMOVE_ALL);
        http_add_header_field(&res->hdr, "Via", buf2);
    }

    const char *location = http_get_header_field(&res->hdr, "Location");
    if (location != NULL) {
        char *hostnames[] = {conf->name, conf->proxy.hostname};
        for (int i = 0; i < sizeof(hostnames) / sizeof(hostnames[0]); i++) {
            char *hostname = hostnames[i];

            p_len = snprintf(buf1, sizeof(buf1), "http://%s/", hostname);
            if (strncmp(location, buf1, p_len) == 0) goto match;

            p_len = snprintf(buf1, sizeof(buf1), "https://%s/", hostname);
            if (strncmp(location, buf1, p_len) == 0) goto match;

            p_len = snprintf(buf1, sizeof(buf1), "http://%s:%i/", hostname, conf->proxy.port);
            if (strncmp(location, buf1, p_len) == 0) goto match;

            p_len = snprintf(buf1, sizeof(buf1), "https://%s:%i/", hostname, conf->proxy.port);
            if (strncmp(location, buf1, p_len) == 0) goto match;
        }

        if (0) {
            match:
            strcpy(buf1, location + p_len - 1);
            http_remove_header_field(&res->hdr, "Location", HTTP_REMOVE_ALL);
            http_add_header_field(&res->hdr, "Location", buf1);
        }
    }

    return 0;
}

int proxy_init(http_req *req, http_res *res, http_status_ctx *ctx, host_config_t *conf, sock *client, client_ctx_t *cctx, http_status *custom_status, char *err_msg) {
    char buffer[CHUNK_SIZE];
    const char *connection, *upgrade, *ws_version;
    long ret;
    int tries = 0, retry = 0;

    if (proxy.socket != 0 && strcmp(proxy_host, conf->name) == 0 && sock_check(&proxy) == 0)
        goto proxy;

    retry:
    if (proxy.socket != 0) {
        info(BLUE_STR "Closing proxy connection");
        sock_close(&proxy);
    }
    retry = 0;
    tries++;

    proxy.socket = socket(AF_INET6, SOCK_STREAM, 0);
    if (proxy.socket  < 0) {
        error("Unable to create socket");
        res->status = http_get_status(500);
        ctx->origin = INTERNAL;
        return -1;
    }

    server_timeout.tv_sec = SERVER_TIMEOUT_INIT;
    server_timeout.tv_usec = 0;
    if (setsockopt(proxy.socket, SOL_SOCKET, SO_RCVTIMEO, &server_timeout, sizeof(server_timeout)) < 0)
        goto proxy_timeout_err;
    if (setsockopt(proxy.socket, SOL_SOCKET, SO_SNDTIMEO, &server_timeout, sizeof(server_timeout)) < 0)
        goto proxy_timeout_err;

    struct hostent *host_ent = gethostbyname2(conf->proxy.hostname, AF_INET6);
    if (host_ent == NULL) {
        host_ent = gethostbyname2(conf->proxy.hostname, AF_INET);
        if (host_ent == NULL) {
            res->status = http_get_status(503);
            ctx->origin = SERVER_REQ;
            error("Unable to connect to server: Name or service not known");
            sprintf(err_msg, "Unable to connect to server: Name or service not known.");
            goto proxy_err;
        }
    }

    struct sockaddr_in6 address = {.sin6_family = AF_INET6, .sin6_port = htons(conf->proxy.port)};
    if (host_ent->h_addrtype == AF_INET6) {
        memcpy(&address.sin6_addr, host_ent->h_addr_list[0], host_ent->h_length);
    } else if (host_ent->h_addrtype == AF_INET) {
        unsigned char addr[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0};
        memcpy(addr + 12, host_ent->h_addr_list[0], host_ent->h_length);
        memcpy(&address.sin6_addr, addr, 16);
    }

    inet_ntop(address.sin6_family, (void *) &address.sin6_addr, buffer, sizeof(buffer));

    info(BLUE_STR "Connecting to " BLD_STR "[%s]:%i" CLR_STR BLUE_STR "...", buffer, conf->proxy.port);
    if (connect(proxy.socket, (struct sockaddr *) &address, sizeof(address)) < 0) {
        if (errno == ETIMEDOUT || errno == EINPROGRESS) {
            res->status = http_get_status(504);
            ctx->origin = SERVER_REQ;
        } else if (errno == ECONNREFUSED) {
            res->status = http_get_status(503);
            ctx->origin = SERVER_REQ;
        } else {
            res->status = http_get_status(500);
            ctx->origin = INTERNAL;
        }
        error("Unable to connect to [%s]:%i: %s", buffer, conf->proxy.port, strerror(errno));
        sprintf(err_msg, "Unable to connect to server: %s.", strerror(errno));
        goto proxy_err;
    }

    server_timeout.tv_sec = SERVER_TIMEOUT;
    server_timeout.tv_usec = 0;
    if (setsockopt(proxy.socket, SOL_SOCKET, SO_RCVTIMEO, &server_timeout, sizeof(server_timeout)) < 0)
        goto proxy_timeout_err;
    if (setsockopt(proxy.socket, SOL_SOCKET, SO_SNDTIMEO, &server_timeout, sizeof(server_timeout)) < 0) {
        proxy_timeout_err:
        res->status = http_get_status(500);
        ctx->origin = INTERNAL;
        error("Unable to set timeout for reverse proxy socket");
        sprintf(err_msg, "Unable to set timeout for reverse proxy socket: %s", strerror(errno));
        goto proxy_err;
    }

    if (conf->proxy.enc) {
        proxy.ssl = SSL_new(proxy.ctx);
        SSL_set_fd(proxy.ssl, proxy.socket);
        SSL_set_connect_state(proxy.ssl);

        ret = SSL_do_handshake(proxy.ssl);
        proxy._last_ret = ret;
        proxy._errno = errno;
        proxy._ssl_error = ERR_get_error();
        proxy.enc = 1;
        if (ret < 0) {
            res->status = http_get_status(502);
            ctx->origin = SERVER_REQ;
            error("Unable to perform handshake: %s", sock_strerror(&proxy));
            sprintf(err_msg, "Unable to perform handshake: %s.", sock_strerror(&proxy));
            goto proxy_err;
        }
    }

    proxy_host = conf->name;
    info(BLUE_STR "Established new connection with " BLD_STR "[%s]:%i", buffer, conf->proxy.port);

    proxy:
    connection = http_get_header_field(&req->hdr, "Connection");
    if (connection != NULL && (strstr(connection, "upgrade") != NULL || strstr(connection, "Upgrade") != NULL)) {
        upgrade = http_get_header_field(&req->hdr, "Upgrade");
        ws_version = http_get_header_field(&req->hdr, "Sec-WebSocket-Version");
        if (upgrade != NULL && ws_version != NULL && strcmp(upgrade, "websocket") == 0 && strcmp(ws_version, "13") == 0) {
            ctx->ws_key = http_get_header_field(&req->hdr, "Sec-WebSocket-Key");
        } else {
            res->status = http_get_status(501);
            ctx->origin = INTERNAL;
            return -1;
        }
    } else {
        http_remove_header_field(&req->hdr, "Connection", HTTP_REMOVE_ALL);
        http_add_header_field(&req->hdr, "Connection", "keep-alive");
    }

    ret = proxy_request_header(req, (int) client->enc, cctx);
    if (ret != 0) {
        res->status = http_get_status(500);
        ctx->origin = INTERNAL;
        return -1;
    }

    ret = http_send_request(&proxy, req);
    if (ret < 0) {
        res->status = http_get_status(502);
        ctx->origin = SERVER_REQ;
        error("Unable to send request to server (1): %s", sock_strerror(&proxy));
        sprintf(err_msg, "Unable to send request to server: %s.", sock_strerror(&proxy));
        retry = tries < 4;
        goto proxy_err;
    }

    const char *content_length = http_get_header_field(&req->hdr, "Content-Length");
    unsigned long content_len = content_length != NULL ? strtoul(content_length, NULL, 10) : 0;
    const char *transfer_encoding = http_get_header_field(&req->hdr, "Transfer-Encoding");

    ret = 0;
    if (content_len > 0) {
        ret = sock_splice(&proxy, client, buffer, sizeof(buffer), content_len);
    } else if (transfer_encoding != NULL && strstr(transfer_encoding, "chunked") != NULL) {
        ret = sock_splice_chunked(&proxy, client, buffer, sizeof(buffer));
    }

    if (ret < 0 || (content_len != 0 && ret != content_len)) {
        if (ret == -1) {
            res->status = http_get_status(502);
            ctx->origin = SERVER_REQ;
            error("Unable to send request to server (2): %s", sock_strerror(&proxy));
            sprintf(err_msg, "Unable to send request to server: %s.", sock_strerror(&proxy));
            retry = tries < 4;
            goto proxy_err;
        } else if (ret == -2) {
            res->status = http_get_status(400);
            ctx->origin = CLIENT_REQ;
            error("Unable to receive request from client: %s", sock_strerror(client));
            sprintf(err_msg, "Unable to receive request from client: %s.", sock_strerror(client));
            return -1;
        }
        res->status = http_get_status(500);
        ctx->origin = INTERNAL;
        error("Unknown Error");
        return -1;
    }

    ret = sock_recv(&proxy, buffer, sizeof(buffer), MSG_PEEK);
    if (ret <= 0) {
        int enc_err = sock_enc_error(&proxy);
        if (errno == EAGAIN || errno == EINPROGRESS || enc_err == SSL_ERROR_WANT_READ ||
            enc_err == SSL_ERROR_WANT_WRITE)
        {
            res->status = http_get_status(504);
            ctx->origin = SERVER_RES;
        } else {
            res->status = http_get_status(502);
            ctx->origin = SERVER_RES;
        }
        error("Unable to receive response from server: %s", sock_strerror(&proxy));
        sprintf(err_msg, "Unable to receive response from server: %s.", sock_strerror(&proxy));
        retry = tries < 4;
        goto proxy_err;
    }

    char *buf = buffer;
    unsigned short header_len = (unsigned short) (strstr(buffer, "\r\n\r\n") - buffer + 4);

    if (header_len <= 0) {
        res->status = http_get_status(502);
        ctx->origin = SERVER_RES;
        error("Unable to parse header: End of header not found");
        sprintf(err_msg, "Unable to parser header: End of header not found.");
        goto proxy_err;
    }

    for (int i = 0; i < header_len; i++) {
        if ((buf[i] >= 0x00 && buf[i] <= 0x1F && buf[i] != '\r' && buf[i] != '\n') || buf[i] == 0x7F) {
            res->status = http_get_status(502);
            ctx->origin = SERVER_RES;
            error("Unable to parse header: Header contains illegal characters");
            sprintf(err_msg, "Unable to parse header: Header contains illegal characters.");
            goto proxy_err;
        }
    }

    char *ptr = buf;
    while (header_len != (ptr - buf)) {
        char *pos0 = strstr(ptr, "\r\n");
        if (pos0 == NULL) {
            res->status = http_get_status(502);
            ctx->origin = SERVER_RES;
            error("Unable to parse header: Invalid header format");
            sprintf(err_msg, "Unable to parse header: Invalid header format.");
            goto proxy_err;
        }
        if (ptr == buf) {
            if (strncmp(ptr, "HTTP/", 5) != 0) {
                res->status = http_get_status(502);
                ctx->origin = SERVER_RES;
                error("Unable to parse header: Invalid header format");
                sprintf(err_msg, "Unable to parse header: Invalid header format.");
                goto proxy_err;
            }
            int status_code = (int) strtol(ptr + 9, NULL, 10);
            res->status = http_get_status(status_code);
            if (res->status == NULL && status_code >= 100 && status_code <= 999) {
                custom_status->code = status_code;
                strcpy(custom_status->type, "");
                snprintf(custom_status->msg, sizeof(custom_status->msg), "%.*s",
                         (int) (strchr(ptr, '\r') - ptr - 13), ptr + 13);
                res->status = custom_status;
            } else if (res->status == NULL) {
                res->status = http_get_status(502);
                ctx->origin = SERVER_RES;
                error("Unable to parse header: Invalid or unknown status code");
                sprintf(err_msg, "Unable to parse header: Invalid or unknown status code.");
                goto proxy_err;
            }
        } else {
            ret = http_parse_header_field(&res->hdr, ptr, pos0, 0);
            if (ret != 0) {
                res->status = http_get_status(502);
                ctx->origin = SERVER_RES;
                error("Unable to parse header");
                sprintf(err_msg, "Unable to parse header.");
                goto proxy_err;
            }
        }
        if (pos0[2] == '\r' && pos0[3] == '\n') {
            break;
        }
        ptr = pos0 + 2;
    }
    sock_recv(&proxy, buffer, header_len, 0);

    ret = proxy_response_header(req, res, conf);
    if (ret != 0) {
        res->status = http_get_status(500);
        ctx->origin = INTERNAL;
        return -1;
    }

    return 0;

    proxy_err:
    if (retry) goto retry;
    return -1;
}

int proxy_send(sock *client, unsigned long len_to_send, int flags) {
    char buffer[CHUNK_SIZE], comp_out[CHUNK_SIZE], buf[256], *ptr;
    long ret = 0, len, snd_len;
    int finish_comp = 0;

    compress_ctx comp_ctx;
    if (flags & PROXY_COMPRESS_BR) {
        flags &= ~PROXY_COMPRESS_GZ;
        if (compress_init(&comp_ctx, COMPRESS_BR) != 0) {
            error("Unable to init brotli");
            flags &= ~PROXY_COMPRESS_BR;
        }
    } else if (flags & PROXY_COMPRESS_GZ) {
        flags &= ~PROXY_COMPRESS_BR;
        if (compress_init(&comp_ctx, COMPRESS_GZ) != 0) {
            error("Unable to init gzip");
            flags &= ~PROXY_COMPRESS_GZ;
        }
    }

    do {
        snd_len = 0;
        if (flags & PROXY_CHUNKED) {
            ret = sock_get_chunk_header(&proxy);
            if (ret < 0) {
                if (ret == -1) {
                    error("Unable to receive from server: Malformed chunk header");
                } else {
                    error("Unable to receive from server: %s", sock_strerror(&proxy));
                }
                break;
            }

            len_to_send = ret;
            ret = 1;
            if (len_to_send == 0 && (flags & PROXY_COMPRESS)) {
                finish_comp = 1;
                len = 0;
                ptr = NULL;
                goto out;
                finish:
                compress_free(&comp_ctx);
            }
        }
        while (snd_len < len_to_send) {
            unsigned long avail_in, avail_out;
            ret = sock_recv(&proxy, buffer, CHUNK_SIZE < (len_to_send - snd_len) ? CHUNK_SIZE : len_to_send - snd_len, 0);
            if (ret <= 0) {
                error("Unable to receive from server: %s", sock_strerror(&proxy));
                break;
            }
            len = ret;
            ptr = buffer;
            out:
            avail_in = len;
            char *next_in = ptr;
            do {
                long buf_len = len;
                if (flags & PROXY_COMPRESS) {
                    avail_out = sizeof(comp_out);
                    compress_compress(&comp_ctx, next_in + len - avail_in, &avail_in, comp_out, &avail_out, finish_comp);
                    ptr = comp_out;
                    buf_len = (int) (sizeof(comp_out) - avail_out);
                    snd_len += (long) (len - avail_in);
                }
                if (buf_len != 0) {
                    len = sprintf(buf, "%lX\r\n", buf_len);
                    ret = 1;

                    if (flags & PROXY_CHUNKED) ret = sock_send(client, buf, len, 0);
                    if (ret <= 0) goto err;

                    ret = sock_send(client, ptr, buf_len, 0);
                    if (ret <= 0) goto err;
                    if (!(flags & PROXY_COMPRESS)) snd_len += ret;

                    if (flags & PROXY_CHUNKED) ret = sock_send(client, "\r\n", 2, 0);
                    if (ret <= 0) {
                        err:
                        error("Unable to send: %s", sock_strerror(client));
                        break;
                    }
                }
            } while ((flags & PROXY_COMPRESS) && (avail_in != 0 || avail_out != sizeof(comp_out)));
            if (ret <= 0) break;
            if (finish_comp) goto finish;
        }
        if (ret <= 0) break;
        if (flags & PROXY_CHUNKED) sock_recv(&proxy, buffer, 2, 0);
    } while ((flags & PROXY_CHUNKED) && len_to_send > 0);

    if (ret <= 0) return -1;

    if (flags & PROXY_CHUNKED) {
        ret = sock_send(client, "0\r\n\r\n", 5, 0);
        if (ret <= 0) {
            error("Unable to send: %s", sock_strerror(client));
            return -1;
        }
    }

    return 0;
}

int proxy_dump(char *buf, long len) {
    sock_recv(&proxy, buf, len, 0);
    sock_close(&proxy);
    return 0;
}
