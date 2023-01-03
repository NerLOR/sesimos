/**
 * sesimos - secure, simple, modern web server
 * @brief Proxy handler
 * @file src/worker/proxy_handler_1.c
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#include "func.h"
#include "../logger.h"
#include "../lib/utils.h"
#include "../lib/proxy.h"
#include "../lib/websocket.h"
#include "../workers.h"

#include <string.h>
#include <errno.h>

static int proxy_handler_1(client_ctx_t *ctx);
static int proxy_handler_2(client_ctx_t *ctx);

void proxy_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%s%*s%s]%s", BLD_STR, INET6_ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);

    int ret = proxy_handler_1(ctx);
    respond(ctx);

    if (ret == 1) {

    } else if (ctx->use_proxy == 0) {
        proxy_close(ctx->proxy);
    } else if (ctx->use_proxy == 1) {
        proxy_handler_2(ctx);
    } else if (ctx->use_proxy == 2) {
        // WebSocket
        ws_handle_connection(ctx);
        return;
    }

    request_complete(ctx);
    handle_request(ctx);
}

static int proxy_handler_1(client_ctx_t *ctx) {
    http_res *res = &ctx->res;
    http_status_ctx *status = &ctx->status;

    char buf[1024];

    info("Reverse proxy for " BLD_STR "%s:%i" CLR_STR, ctx->conf->proxy.hostname, ctx->conf->proxy.port);
    http_remove_header_field(&res->hdr, "Date", HTTP_REMOVE_ALL);
    http_remove_header_field(&res->hdr, "Server", HTTP_REMOVE_ALL);

    ctx->use_proxy = proxy_init(&ctx->proxy, &ctx->req, res, status, ctx->conf, &ctx->socket, &ctx->custom_status, ctx->err_msg) == 0;

    if (res->status->code == 101) {
        const char *connection = http_get_header_field(&res->hdr, "Connection");
        const char *upgrade = http_get_header_field(&res->hdr, "Upgrade");
        if (connection != NULL && upgrade != NULL &&
            (strstr(connection, "upgrade") != NULL || strstr(connection, "Upgrade") != NULL) &&
             strcmp(upgrade, "websocket") == 0)
        {
            const char *ws_accept = http_get_header_field(&res->hdr, "Sec-WebSocket-Accept");
            if (ws_calc_accept_key(status->ws_key, buf) == 0) {
                ctx->use_proxy = (strcmp(buf, ws_accept) == 0) ? 2 : 1;
            }
        } else {
            status->status = 101;
            status->origin = INTERNAL;
            res->status = http_get_status(501);
        }
    }

    // Let 300 be formatted by origin server
    if (ctx->use_proxy && res->status->code >= 301 && res->status->code < 600) {
        const char *content_type = http_get_header_field(&res->hdr, "Content-Type");
        const char *content_length_f = http_get_header_field(&res->hdr, "Content-Length");
        const char *content_encoding = http_get_header_field(&res->hdr, "Content-Encoding");
        if (content_encoding == NULL && (
                (content_length_f != NULL && strcmp(content_length_f, "0") == 0) ||
                (content_type != NULL && content_length_f != NULL && strncmp(content_type, "text/html", 9) == 0)))
        {
            long content_len = strtol(content_length_f, NULL, 10);
            if (content_len <= sizeof(ctx->msg_content) - 1) {
                if (status->status != 101) {
                    status->status = res->status->code;
                    status->origin = res->status->code >= 400 ? SERVER : NONE;
                }
                ctx->use_proxy = 0;

                if (content_len > 0)
                    proxy_dump(ctx->proxy, ctx->msg_content, content_len);

                return 1;
            }
        }
    }

    /*
    char *content_encoding = http_get_header_field(&res->hdr, "Content-Encoding");
    if (use_proxy && content_encoding == NULL) {
        int http_comp = http_get_compression(&req, &res);
        if (http_comp & COMPRESS_BR) {
            use_proxy |= PROXY_COMPRESS_BR;
        } else if (http_comp & COMPRESS_GZ) {
            use_proxy |= PROXY_COMPRESS_GZ;
        }
    }

    char *transfer_encoding = http_get_header_field(&res->hdr, "Transfer-Encoding");
    int chunked = transfer_encoding != NULL && strcmp(transfer_encoding, "chunked") == 0;
    http_remove_header_field(&res->hdr, "Transfer-Encoding", HTTP_REMOVE_ALL);
    ret = sprintf(buf, "%s%s%s",
                  (use_proxy & PROXY_COMPRESS_BR) ? "br" :
                  ((use_proxy & PROXY_COMPRESS_GZ) ? "gzip" : ""),
                  ((use_proxy & PROXY_COMPRESS) && chunked) ? ", " : "",
                  chunked ? "chunked" : "");
    if (ret > 0) {
        http_add_header_field(&res->hdr, "Transfer-Encoding", buf);
    }
    */

    return 0;
}

static int proxy_handler_2(client_ctx_t *ctx) {
    const char *transfer_encoding = http_get_header_field(&ctx->res.hdr, "Transfer-Encoding");
    int chunked = transfer_encoding != NULL && strstr(transfer_encoding, "chunked") != NULL;

    const char *content_len = http_get_header_field(&ctx->res.hdr, "Content-Length");
    unsigned long len_to_send = 0;
    if (content_len != NULL) {
        len_to_send = strtol(content_len, NULL, 10);
    }

    int flags = (chunked ? PROXY_CHUNKED : 0) | (ctx->use_proxy & PROXY_COMPRESS);
    int ret = proxy_send(ctx->proxy, &ctx->socket, len_to_send, flags);
    ctx->proxy->in_use = 0;
    ctx->proxy = NULL;

    if (ret < 0) {
        ctx->c_keep_alive = 0;
    }

    return ret;
}

void proxy_close(proxy_ctx_t *ctx) {
    info(BLUE_STR "Closing proxy connection");
    sock_close(&ctx->proxy);

    memset(ctx, 0, sizeof(*ctx));
    errno = 0;
}
