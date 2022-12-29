/**
 * sesimos - secure, simple, modern web server
 * @brief TCP closer
 * @file src/worker/fastcgi_handler.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "fastcgi_handler.h"
#include "../logger.h"
#include "../lib/mpmc.h"
#include "../lib/utils.h"

static mpmc_t mpmc_ctx;

static void fastcgi_handler_func(client_ctx_t *ctx);

int fastcgi_handler_init(int n_workers, int buf_size) {
    return mpmc_init(&mpmc_ctx, n_workers, buf_size, (void (*)(void *)) fastcgi_handler_func, "fcgi");
}

int fastcgi_handle(client_ctx_t *ctx) {
    return mpmc_queue(&mpmc_ctx, ctx);
}

void fastcgi_handler_stop(void) {
    mpmc_stop(&mpmc_ctx);
}

void fastcgi_handler_destroy(void) {
    mpmc_destroy(&mpmc_ctx);
}

static void fastcgi_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%s%*s%s]%s", BLD_STR, INET6_ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);
    // TODO
}
