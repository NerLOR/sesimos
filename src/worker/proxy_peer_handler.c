/**
 * sesimos - secure, simple, modern web server
 * @brief Proxy peer handler
 * @file src/worker/proxy_peer_handler.c
 * @author Lorenz Stechauner
 * @date 2023-07-07
 */

#include "func.h"
#include "../logger.h"
#include "../lib/utils.h"

void proxy_peer_handler_func(proxy_ctx_t *ctx) {
    if (!ctx->initialized || ctx->in_use) return;
    logger_set_prefix("[%s%*s%s]", BLD_STR, ADDRSTRLEN, ctx->host, CLR_STR);
    proxy_close(ctx);
}
