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

static int proxy_handler(client_ctx_t *ctx);

void proxy_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%s%*s%s]%s", BLD_STR, INET6_ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);

    proxy_handler(ctx);
    respond(ctx);
}

static int proxy_handler(client_ctx_t *ctx) {
    http_res *res = &ctx->res;
    http_req *req = &ctx->req;
    http_uri *uri = &ctx->uri;
    http_status_ctx *status = &ctx->status;
    sock *client = &ctx->socket;
    char *err_msg = ctx->err_msg;

    char buf[1024];

    info("Reverse proxy for " BLD_STR "%s:%i" CLR_STR, ctx->conf->proxy.hostname, ctx->conf->proxy.port);
    http_remove_header_field(&res->hdr, "Date", HTTP_REMOVE_ALL);
    http_remove_header_field(&res->hdr, "Server", HTTP_REMOVE_ALL);

    int ret = proxy_init(req, res, status, ctx->conf, client, ctx, &ctx->custom_status, err_msg);
    ctx->use_proxy = (ret == 0);

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
        if (content_encoding == NULL && content_type != NULL && content_length_f != NULL && strncmp(content_type, "text/html", 9) == 0) {
            long content_len = strtol(content_length_f, NULL, 10);
            if (content_len <= sizeof(ctx->msg_content) - 1) {
                if (status->status != 101) {
                    status->status = res->status->code;
                    status->origin = res->status->code >= 400 ? SERVER : NONE;
                }
                ctx->use_proxy = 0;
                proxy_dump(ctx->msg_content, content_len);
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
