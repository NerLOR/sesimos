/**
 * sesimos - secure, simple, modern web server
 * @brief TCP closer
 * @file src/worker/tcp_closer.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "func.h"
#include "../logger.h"
#include "../lib/utils.h"

#include <memory.h>

void tcp_closer_func(client_ctx_t *ctx) {
    logger_set_prefix("[%*s]%s", INET6_ADDRSTRLEN, ctx->socket.s_addr, ctx->log_prefix);

    sock_close(&ctx->socket);

    ctx->cnx_e = clock_micros();
    char buf[32];
    info("Connection closed (%s)", format_duration(ctx->cnx_e - ctx->cnx_s, buf));

    memset(ctx, 0, sizeof(*ctx));
}
