
#include "request_handler.h"
#include "../logger.h"
#include "../lib/mpmc.h"
#include "../lib/utils.h"
#include "tcp_closer.h"
#include "../async.h"
#include "../server.h"

static mpmc_t mpmc_ctx;

static void request_handler_func(client_ctx_t *ctx);

int request_handler_init(int n_workers, int buf_size) {
    return mpmc_init(&mpmc_ctx, n_workers, buf_size, (void (*)(void *)) request_handler_func, "req");
}

int handle_request(client_ctx_t *ctx) {
    return mpmc_queue(&mpmc_ctx, ctx);
}

void request_handler_stop(void) {
    mpmc_stop(&mpmc_ctx);
}

void request_handler_destroy(void) {
    mpmc_destroy(&mpmc_ctx);
}

static void request_handler_func(client_ctx_t *ctx) {
    client_request_handler(ctx);

    if (ctx->c_keep_alive && ctx->s_keep_alive && ctx->req_num < REQ_PER_CONNECTION) {
        async(ctx->socket.socket, POLLIN, 0, (void (*)(void *)) handle_request, ctx, (void (*)(void *)) tcp_close, ctx);
        logger_set_prefix(ctx->log_prefix);
    } else {
        tcp_close(ctx);
    }
}
