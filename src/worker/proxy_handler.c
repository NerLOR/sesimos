/**
 * sesimos - secure, simple, modern web server
 * @brief Proxy handler
 * @file src/worker/proxy_handler.c
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

static int proxy_handler_1(client_ctx_t *ctx);
static int proxy_handler_2(client_ctx_t *ctx);

void proxy_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%s%*s%s]%s", BLD_STR, ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);

    // TODO handle 1xx responses

    int ret = proxy_handler_1(ctx);
    respond(ctx);

    if (ret == 1) {
        // error status code
        if (proxy_unlock_ctx(ctx->proxy) == 1)
            proxy_peer_handle(ctx->proxy);
    } else if (ctx->use_proxy == 0) {
        // proxy not used
        proxy_close(ctx->proxy);
        proxy_unlock_ctx(ctx->proxy);
    } else if (ctx->use_proxy == 1) {
        // proxy is used
        if (proxy_handler_2(ctx) == 1) {
            // chunked
            return;
        }
        if (proxy_unlock_ctx(ctx->proxy) == 1)
            proxy_peer_handle(ctx->proxy);
    } else if (ctx->use_proxy == 2) {
        // WebSocket
        ws_handle_connection(ctx);
        return;
    }

    ctx->proxy = NULL;
    request_complete(ctx);
    handle_request(ctx);
}

static int proxy_handler_1(client_ctx_t *ctx) {
    http_res *res = &ctx->res;
    http_status_ctx *status = &ctx->status;

    char buf[1024];

    info("Reverse proxy for " BLD_STR "[%s]:%i" CLR_STR, ctx->conf->proxy.hostname, ctx->conf->proxy.port);
    http_remove_header_field(&res->hdr, "Date", HTTP_REMOVE_ALL);
    http_remove_header_field(&res->hdr, "Server", HTTP_REMOVE_ALL);

    ctx->use_proxy = proxy_init(&ctx->proxy, &ctx->req, res, status, ctx->conf, &ctx->socket, &ctx->custom_status, ctx->err_msg) == 0;
    ctx->proxy->client = ctx;

    if (ctx->use_proxy == 0)
        return 0;

    if (res->status->code == 101) {
        const char *connection = http_get_header_field(&res->hdr, "Connection");
        const char *upgrade = http_get_header_field(&res->hdr, "Upgrade");
        if (connection != NULL && upgrade != NULL &&
            (strcontains(connection, "upgrade") || strcontains(connection, "Upgrade")) &&
            streq(upgrade, "websocket"))
        {
            const char *ws_accept = http_get_header_field(&res->hdr, "Sec-WebSocket-Accept");
            if (ws_calc_accept_key(status->ws_key, buf) == 0) {
                ctx->use_proxy = streq(buf, ws_accept) ? 2 : 1;
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
        const char *transfer_encoding = http_get_header_field(&res->hdr, "Transfer-Encoding");
        if (transfer_encoding == NULL && content_encoding == NULL && (
                content_length_f == NULL ||
                streq(content_length_f, "0") ||
                (content_length_f != NULL && strstarts(content_type, "text/html"))))
        {
            long content_len = (!streq(ctx->req.method, "HEAD") && content_length_f != NULL) ? strtol(content_length_f, NULL, 10) : 0;
            if (content_len < sizeof(ctx->msg_content)) {
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

    return streq(ctx->req.method, "HEAD") ? 1 : 0;
}

static void proxy_chunk_next_cb(chunk_ctx_t *ctx) {
    if (proxy_unlock_ctx(ctx->client->proxy) == 1)
        proxy_peer_handle(ctx->client->proxy);

    ctx->client->proxy = NULL;
    request_complete(ctx->client);
    handle_request(ctx->client);
}

static void proxy_chunk_err_cb(chunk_ctx_t *ctx) {
    ctx->client->c_keep_alive = 0;
    proxy_close(ctx->client->proxy);
    proxy_unlock_ctx(ctx->client->proxy);

    ctx->client->proxy = NULL;
    request_complete(ctx->client);
    handle_request(ctx->client);
}

static int proxy_handler_2(client_ctx_t *ctx) {
    const char *transfer_encoding = http_get_header_field(&ctx->res.hdr, "Transfer-Encoding");
    int chunked = strcontains(transfer_encoding, "chunked");

    const char *content_len = http_get_header_field(&ctx->res.hdr, "Content-Length");
    unsigned long len_to_send = (content_len != NULL) ? strtol(content_len, NULL, 10) : 0;

    if (chunked) {
        handle_chunks(ctx, &ctx->proxy->proxy, SOCK_CHUNKED, proxy_chunk_next_cb, proxy_chunk_err_cb);
        return 1;
    }

    int ret;
    if ((ret = proxy_send(ctx->proxy, &ctx->socket, len_to_send, 0)) == -1) {
        ctx->c_keep_alive = 0;
    }

    return ret;
}
