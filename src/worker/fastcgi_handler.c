/**
 * sesimos - secure, simple, modern web server
 * @brief TCP closer
 * @file src/worker/fastcgi_handler.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "func.h"
#include "../logger.h"
#include "../lib/utils.h"

void fastcgi_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%s%*s%s]%s", BLD_STR, INET6_ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);
    // TODO
}
