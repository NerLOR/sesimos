/**
 * sesimos - secure, simple, modern web server
 * @brief TCP closer
 * @file src/worker/tcp_closer.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "tcp_closer.h"
#include "../logger.h"
#include "../lib/utils.h"

#include <memory.h>

void tcp_closer_func(client_ctx_t *ctx) {
    logger_set_prefix("[%*s]%s", INET6_ADDRSTRLEN, ctx->s_addr, ctx->log_prefix);

    sock_close(&ctx->socket);

    char buf[32];
    clock_gettime(CLOCK_MONOTONIC, &ctx->end);
    unsigned long micros = (ctx->end.tv_nsec - ctx->begin.tv_nsec) / 1000 + (ctx->end.tv_sec - ctx->begin.tv_sec) * 1000000;
    info("Connection closed (%s)", format_duration(micros, buf));

    memset(ctx, 0, sizeof(*ctx));
}
