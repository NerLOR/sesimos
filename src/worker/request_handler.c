
#include "request_handler.h"
#include "../logger.h"
#include "../lib/mpmc.h"
#include "../lib/utils.h"
#include "tcp_closer.h"

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
    // TODO
    tcp_close(ctx);
}
