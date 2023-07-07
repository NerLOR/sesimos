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
#include "config.h"
#include "error.h"

#include <openssl/ssl.h>
#include <string.h>
#include <errno.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <semaphore.h>

static SSL_CTX *proxy_ctx = NULL;
static proxy_ctx_t *proxies = NULL;
static sem_t *available = NULL;
static sem_t lock;
static int num_proxy_hosts = -1;

int proxy_preload(void) {
    int n = 0;
    for (int i = 0; i < CONFIG_MAX_HOST_CONFIG; i++) {
        host_config_t *hc = &config.hosts[i];
        if (hc->type == CONFIG_TYPE_UNSET) break;
        if (hc->type != CONFIG_TYPE_REVERSE_PROXY) continue;
        n++;
    }

    proxy_ctx = SSL_CTX_new(TLS_client_method());
    if (proxy_ctx == NULL) {
        return -1;
    }

    proxies = malloc(n * MAX_PROXY_CNX_PER_HOST * sizeof(proxy_ctx_t));
    if (proxies == NULL) {
        proxy_unload();
        return -1;
    }
    memset(proxies, 0, n * MAX_PROXY_CNX_PER_HOST * sizeof(proxy_ctx_t));

    available = malloc(n * sizeof(*available));
    if (available == NULL) {
        proxy_unload();
        return -1;
    }
    for (int i = 0; i < n; i++) {
        if (sem_init(&available[i], 0, MAX_PROXY_CNX_PER_HOST) != 0) {
            proxy_unload();
            return -1;
        }
    }

    if (sem_init(&lock, 0, 1) != 0) {
        proxy_unload();
        return -1;
    }

    num_proxy_hosts = n;

    return 0;
}

void proxy_unload(void) {
    int e = errno;
    SSL_CTX_free(proxy_ctx);
    sem_destroy(&lock);
    if (num_proxy_hosts != -1) {
        for (int i = 0; i < num_proxy_hosts; i++) {
            sem_destroy(&available[i]);
        }
    }
    free(available);
    free(proxies);
    errno = e;
}

void proxy_close_all(void) {
    proxy_ctx_t *ptr = proxies;
    for (int i = 0; i < MAX_PROXY_CNX_PER_HOST * num_proxy_hosts; i++, ptr++) {
        if (ptr->initialized) {
            proxy_close(ptr);
            logger_set_prefix("");
        }
    }
}

proxy_ctx_t *proxy_get_by_conf(host_config_t *conf) {
    int n = 0;
    for (int i = 0; i < CONFIG_MAX_HOST_CONFIG; i++) {
        host_config_t *hc = &config.hosts[i];
        if (hc->type == CONFIG_TYPE_UNSET) break;
        if (hc->type != CONFIG_TYPE_REVERSE_PROXY) continue;
        if (hc == conf) break;
        n++;
    }

    while (sem_wait(&available[n]) != 0) {
        if (errno == EINTR) {
            errno = 0;
            continue;
        } else {
            return NULL;
        }
    }

    while (sem_wait(&lock) != 0) {
        if (errno == EINTR) {
            errno = 0;
            continue;
        } else {
            sem_post(&available[n]);
            return NULL;
        }
    }

    proxy_ctx_t *ptr = proxies + n * MAX_PROXY_CNX_PER_HOST;
    for (int i = 0; i < MAX_PROXY_CNX_PER_HOST; i++, ptr++) {
        if (!ptr->in_use) {
            ptr->in_use = 1;
            sem_post(&lock);
            return ptr;
        }
    }

    sem_post(&lock);
    sem_post(&available[n]);
    return NULL;
}

int proxy_unlock_ctx(proxy_ctx_t *ctx) {
    int n = (int) ((ctx - proxies) / MAX_PROXY_CNX_PER_HOST);
    if (ctx->close) proxy_close(ctx);

    debug("Released proxy connection slot %i/%i", (ctx - proxies) % MAX_PROXY_CNX_PER_HOST, MAX_PROXY_CNX_PER_HOST);
    ctx->in_use = 0;
    ctx->client = NULL;
    sem_post(&available[n]);
    if (!ctx->close) {
        return 1;
    } else {
        ctx->close = 0;
        return 0;
    }
}

int proxy_request_header(http_req *req, sock *sock) {
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

    int client_ipv6 = strchr(sock->addr, ':') != NULL;
    int server_ipv6 = strchr(sock->s_addr, ':') != NULL;

    p_len = snprintf(buf1, sizeof(buf1), "by=%s%s%s;for=%s%s%s;host=%s;proto=%s",
                     server_ipv6 ? "\"[" : "", sock->s_addr, server_ipv6 ? "]\"" : "",
                     client_ipv6 ? "\"[" : "", sock->addr, client_ipv6 ? "]\"" : "",
                     http_get_header_field(&req->hdr, "Host"), sock->enc ? "https" : "http");
    if (p_len < 0 || p_len >= sizeof(buf1)) {
        error("Appended part of header field 'Forwarded' too long");
        return -1;
    }

    const char *forwarded = http_get_header_field(&req->hdr, "Forwarded");
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
        http_add_header_field(&req->hdr, "X-Forwarded-For", sock->addr);
    } else {
        sprintf(buf1, "%s, %s", xff, sock->addr);
        http_remove_header_field(&req->hdr, "X-Forwarded-For", HTTP_REMOVE_ALL);
        http_add_header_field(&req->hdr, "X-Forwarded-For", buf1);
    }

    const char *xfh = http_get_header_field(&req->hdr, "X-Forwarded-Host");
    forwarded = http_get_header_field(&req->hdr, "Forwarded");
    if (xfh == NULL) {
        if (forwarded == NULL) {
            http_add_header_field(&req->hdr, "X-Forwarded-Host", http_get_header_field(&req->hdr, "Host"));
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
    forwarded = http_get_header_field(&req->hdr, "Forwarded");
    if (xfp == NULL) {
        if (forwarded == NULL) {
            http_add_header_field(&req->hdr, "X-Forwarded-Proto", sock->enc ? "https" : "http");
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
        int found = 0;

        for (int i = 0; i < sizeof(hostnames) / sizeof(hostnames[0]); i++) {
            char *hostname = hostnames[i];
            found = 1;

            p_len = snprintf(buf1, sizeof(buf1), "http://%s/", hostname);
            if (strstarts(location, buf1)) break;

            p_len = snprintf(buf1, sizeof(buf1), "https://%s/", hostname);
            if (strstarts(location, buf1)) break;

            p_len = snprintf(buf1, sizeof(buf1), "http://%s:%i/", hostname, conf->proxy.port);
            if (strstarts(location, buf1)) break;

            p_len = snprintf(buf1, sizeof(buf1), "https://%s:%i/", hostname, conf->proxy.port);
            if (strstarts(location, buf1)) break;

            found = 0;
        }

        if (found) {
            strcpy(buf1, location + p_len - 1);
            http_remove_header_field(&res->hdr, "Location", HTTP_REMOVE_ALL);
            http_add_header_field(&res->hdr, "Location", buf1);
        }
    }

    return 0;
}

static int proxy_connect(proxy_ctx_t *proxy, host_config_t *conf, http_res *res, http_status_ctx *ctx, char *err_msg) {
    char err_buf[256], addr_buf[1024];

    info(BLUE_STR "Connecting to " BLD_STR "[%s]:%i" CLR_STR BLUE_STR "...", conf->proxy.hostname, conf->proxy.port);

    int fd;
    if ((fd = sock_connect(conf->proxy.hostname, conf->proxy.port, SERVER_TIMEOUT_INIT, addr_buf, sizeof(addr_buf))) == -1) {
        if (errno == ETIMEDOUT || errno == EINPROGRESS) {
            res->status = http_get_status(504);
            ctx->origin = SERVER_REQ;
        } else if (errno == ECONNREFUSED) {
            res->status = http_get_status(502);
            ctx->origin = SERVER_REQ;
        } else {
            res->status = http_get_status(500);
            ctx->origin = INTERNAL;
        }
        error("Unable to connect to [%s]:%i", addr_buf, conf->proxy.port);
        sprintf(err_msg, "Unable to connect to server: %s.", error_str(errno, err_buf, sizeof(err_buf)));
        return -1;
    }

    sock_init(&proxy->proxy, fd, 0);

    if (sock_set_timeout(&proxy->proxy, SERVER_TIMEOUT) != 0) {
        res->status = http_get_status(500);
        ctx->origin = INTERNAL;
        error("Unable to set timeout for reverse proxy socket");
        sprintf(err_msg, "Unable to set timeout for reverse proxy socket: %s", error_str(errno, err_buf, sizeof(err_buf)));
        return -1;
    }

    if (conf->proxy.enc) {
        proxy->proxy.ssl = SSL_new(proxy_ctx);
        SSL_set_fd(proxy->proxy.ssl, proxy->proxy.socket);
        SSL_set_connect_state(proxy->proxy.ssl);

        int ret;
        if ((ret = SSL_do_handshake(proxy->proxy.ssl)) != 1) {
            sock_error(&proxy->proxy, (int) ret);
            SSL_free(proxy->proxy.ssl);
            proxy->proxy.ssl = NULL;
            res->status = http_get_status(502);
            ctx->origin = SERVER_REQ;
            error("Unable to perform handshake");
            sprintf(err_msg, "Unable to perform handshake: %s.", error_str(errno, err_buf, sizeof(err_buf)));
            return -1;
        }
        proxy->proxy.enc = 1;
    }

    proxy->initialized = 1;
    proxy->cnx_s = clock_micros();
    proxy->host = conf->name;
    proxy->http_timeout = 0;

    info(BLUE_STR "Established new connection with " BLD_STR "[%s]:%i" CLR_STR BLUE_STR " (slot %i/%i)",
         addr_buf, conf->proxy.port, (proxy - proxies) % MAX_PROXY_CNX_PER_HOST, MAX_PROXY_CNX_PER_HOST);

    return 0;
}

int proxy_init(proxy_ctx_t **proxy_ptr, http_req *req, http_res *res, http_status_ctx *ctx, host_config_t *conf, sock *client, http_status *custom_status, char *err_msg) {
    char buffer[CHUNK_SIZE], err_buf[256];
    long ret;

    *proxy_ptr = proxy_get_by_conf(conf);
    proxy_ctx_t *proxy = *proxy_ptr;
    proxy->client = NULL;
    debug("Selected proxy connection slot %i/%i", (proxy - proxies) % MAX_PROXY_CNX_PER_HOST, MAX_PROXY_CNX_PER_HOST);

    const char *connection = http_get_header_field(&req->hdr, "Connection");
    if (strcontains(connection, "upgrade") || strcontains(connection, "Upgrade")) {
        const char *upgrade = http_get_header_field(&req->hdr, "Upgrade");
        const char *ws_version = http_get_header_field(&req->hdr, "Sec-WebSocket-Version");
        if (streq(upgrade, "websocket") && streq(ws_version, "13")) {
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

    ret = proxy_request_header(req, client);
    if (ret != 0) {
        res->status = http_get_status(500);
        ctx->origin = INTERNAL;
        return -1;
    }

    for (int retry = 1, srv_error = 0, tries = 0;; tries++) {
        errno = 0;
        if (!retry)
            return -1;

        // honor server timeout with one second buffer
        if (!proxy->initialized || srv_error ||
            (proxy->http_timeout > 0 && (clock_micros() - proxy->proxy.ts_last_send) >= proxy->http_timeout) ||
            sock_has_pending(&proxy->proxy, SOCK_DONTWAIT))
        {
            if (proxy->initialized)
                proxy_close(proxy);

            retry = 0;
            srv_error = 0;
            tries++;

            if (proxy_connect(proxy, conf, res, ctx, err_msg) != 0)
                continue;
        }

        ret = http_send_request(&proxy->proxy, req);
        if (ret < 0) {
            res->status = http_get_status(502);
            ctx->origin = SERVER_REQ;
            error("Unable to send request to server (1)");
            sprintf(err_msg, "Unable to send request to server: %s.", error_str(errno, err_buf, sizeof(err_buf)));
            retry = tries < 4;
            srv_error = 1;
            continue;
        }

        break;
    }

    const char *content_length = http_get_header_field(&req->hdr, "Content-Length");
    unsigned long content_len = content_length != NULL ? strtoul(content_length, NULL, 10) : 0;
    const char *transfer_encoding = http_get_header_field(&req->hdr, "Transfer-Encoding");

    ret = 0;
    if (content_len > 0) {
        ret = sock_splice(&proxy->proxy, client, buffer, sizeof(buffer), content_len);
    } else if (strcontains(transfer_encoding, "chunked")) {
        ret = sock_splice_chunked(&proxy->proxy, client, buffer, sizeof(buffer), SOCK_CHUNKED);
    }

    if (ret < 0 || (content_len != 0 && ret != content_len)) {
        if (ret == -1 && errno != EPROTO) {
            res->status = http_get_status(502);
            ctx->origin = SERVER_REQ;
            error("Unable to send request to server (2)");
            sprintf(err_msg, "Unable to send request to server: %s.", error_str(errno, err_buf, sizeof(err_buf)));
            return -1;
        } else if (ret == -1) {
            res->status = http_get_status(400);
            ctx->origin = CLIENT_REQ;
            error("Unable to receive request from client");
            sprintf(err_msg, "Unable to receive request from client: %s.", error_str(errno, err_buf, sizeof(err_buf)));
            return -1;
        }
        res->status = http_get_status(500);
        ctx->origin = INTERNAL;
        error("Unknown Error");
        return -1;
    }

    ret = sock_recv(&proxy->proxy, buffer, sizeof(buffer) - 1, MSG_PEEK);
    if (ret <= 0) {
        int e_sys = error_get_sys(), e_ssl = error_get_ssl();
        if (e_sys == EAGAIN || e_sys == EINPROGRESS || e_ssl == SSL_ERROR_WANT_READ || e_ssl == SSL_ERROR_WANT_WRITE) {
            res->status = http_get_status(504);
            ctx->origin = SERVER_RES;
        } else {
            res->status = http_get_status(502);
            ctx->origin = SERVER_RES;
        }
        error("Unable to receive response from server");
        sprintf(err_msg, "Unable to receive response from server: %s.", error_str(errno, err_buf, sizeof(err_buf)));
        return -1;
    }
    buffer[ret] = 0;

    char *buf = buffer;
    unsigned short header_len = (unsigned short) (strstr(buffer, "\r\n\r\n") - buffer + 4);

    if (header_len <= 0) {
        res->status = http_get_status(502);
        ctx->origin = SERVER_RES;
        error("Unable to parse header: End of header not found");
        sprintf(err_msg, "Unable to parser header: End of header not found.");
        return -2;
    }

    for (int i = 0; i < header_len; i++) {
        if ((buf[i] >= 0x00 && buf[i] <= 0x1F && buf[i] != '\r' && buf[i] != '\n') || buf[i] == 0x7F) {
            res->status = http_get_status(502);
            ctx->origin = SERVER_RES;
            error("Unable to parse header: Header contains illegal characters");
            sprintf(err_msg, "Unable to parse header: Header contains illegal characters.");
            return -2;
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
            return -2;
        }
        if (ptr == buf) {
            if (!strstarts(ptr, "HTTP/")) {
                res->status = http_get_status(502);
                ctx->origin = SERVER_RES;
                error("Unable to parse header: Invalid header format");
                sprintf(err_msg, "Unable to parse header: Invalid header format.");
                return -2;
            }
            int status_code = (int) strtol(ptr + 9, NULL, 10);
            res->status = http_get_status(status_code);
            if (res->status == NULL && status_code >= 100 && status_code <= 999) {
                custom_status->code = status_code;
                custom_status->type = 0;
                snprintf(custom_status->msg, sizeof(custom_status->msg), "%.*s",
                         (int) (strchr(ptr, '\r') - ptr - 13), ptr + 13);
                res->status = custom_status;
            } else if (res->status == NULL) {
                res->status = http_get_status(502);
                ctx->origin = SERVER_RES;
                error("Unable to parse header: Invalid or unknown status code");
                sprintf(err_msg, "Unable to parse header: Invalid or unknown status code.");
                return -2;
            }
        } else {
            if (http_parse_header_field(&res->hdr, ptr, pos0, 0) != 0) {
                res->status = http_get_status(502);
                ctx->origin = SERVER_RES;
                error("Unable to parse header");
                sprintf(err_msg, "Unable to parse header.");
                return -2;
            }
        }
        if (pos0[2] == '\r' && pos0[3] == '\n') {
            break;
        }
        ptr = pos0 + 2;
    }
    if (sock_recv_x(&proxy->proxy, buffer, header_len, 0) == -1)
        return -1;

    long keep_alive_timeout = http_get_keep_alive_timeout(&res->hdr);
    proxy->http_timeout = (keep_alive_timeout > 0) ? keep_alive_timeout * 1000000 : 0;

    connection = http_get_header_field(&res->hdr, "Connection");
    proxy->close = !strcontains(connection, "keep-alive") && !strcontains(connection, "Keep-Alive");

    ret = proxy_response_header(req, res, conf);
    if (ret != 0) {
        res->status = http_get_status(500);
        ctx->origin = INTERNAL;
        return -1;
    }

    return 0;
}

int proxy_send(proxy_ctx_t *proxy, sock *client, unsigned long len_to_send, int flags) {
    char buffer[CHUNK_SIZE];
    if (sock_splice(client, &proxy->proxy, buffer, sizeof(buffer), len_to_send) == -1)
        return -1;
    return 0;
}

int proxy_dump(proxy_ctx_t *proxy, char *buf, long len) {
    long ret = sock_recv(&proxy->proxy, buf, len, 0);
    if (ret == -1) return -1;
    buf[ret] = 0;
    return 0;
}

void proxy_close(proxy_ctx_t *ctx) {
    client_ctx_t *cctx = ctx->client;
    if (cctx) {
        logger_set_prefix("[%s%*s%s]%s", BLD_STR, ADDRSTRLEN, cctx->req_host, CLR_STR, cctx->log_prefix);
    }

    if (ctx->initialized) {
        ctx->cnx_e = clock_micros();
        char buf[32];
        info(BLUE_STR "Closing proxy connection %i/%i (%s)",
             (ctx - proxies) % MAX_PROXY_CNX_PER_HOST, MAX_PROXY_CNX_PER_HOST,
             format_duration(ctx->cnx_e - ctx->cnx_s, buf));
    }

    sock_close(&ctx->proxy);
    ctx->initialized = 0;
    ctx->http_timeout = 0;
    ctx->cnx_e = 0, ctx->cnx_s = 0;
    ctx->client = NULL;
    ctx->host = NULL;
    errno = 0;
}
