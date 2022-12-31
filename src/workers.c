/**
 * sesimos - secure, simple, modern web server
 * @brief Worker interface
 * @file src/workers.c
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#include "workers.h"
#include "lib/mpmc.h"

#include "worker/func.h"
#include "async.h"

static mpmc_t tcp_acceptor_ctx, request_handler_ctx,
              local_handler_ctx, fastcgi_handler_cxt, proxy_handler_ctx;

int workers_init(void) {
    mpmc_init(&tcp_acceptor_ctx,     8, 64, (void (*)(void *)) tcp_acceptor_func,    "tcp");
    mpmc_init(&request_handler_ctx, 16, 64, (void (*)(void *)) request_handler_func, "req");
    mpmc_init(&local_handler_ctx,   16, 64, (void (*)(void *)) local_handler_func,   "local");
    mpmc_init(&fastcgi_handler_cxt, 16, 64, (void (*)(void *)) fastcgi_handler_func, "fcgi");
    mpmc_init(&proxy_handler_ctx,   16, 64, (void (*)(void *)) proxy_handler_func,   "proxy");
    return -1;
}

void workers_stop(void) {
    mpmc_stop(&tcp_acceptor_ctx);
    mpmc_stop(&local_handler_ctx);
    mpmc_stop(&fastcgi_handler_cxt);
    mpmc_stop(&proxy_handler_ctx);
    mpmc_stop(&request_handler_ctx);
}

void workers_destroy(void) {
    mpmc_destroy(&tcp_acceptor_ctx);
    mpmc_destroy(&local_handler_ctx);
    mpmc_destroy(&fastcgi_handler_cxt);
    mpmc_destroy(&proxy_handler_ctx);
    mpmc_destroy(&request_handler_ctx);
}

int tcp_accept(client_ctx_t *ctx) {
    return mpmc_queue(&tcp_acceptor_ctx, ctx);
}

static int handle_request_cb(client_ctx_t *ctx) {
    return mpmc_queue(&request_handler_ctx, ctx);
}

int handle_request(client_ctx_t *ctx) {
    if (ctx->c_keep_alive && ctx->s_keep_alive) {
        return async(ctx->socket.socket, POLLIN, 0, (void (*)(void *)) handle_request_cb, ctx, (void (*)(void *)) tcp_close, ctx);
    } else {
        tcp_close(ctx);
        return 0;
    }
}

int local_handle(client_ctx_t *ctx) {
    return mpmc_queue(&local_handler_ctx, ctx);
}

int fastcgi_handle(client_ctx_t *ctx) {
    return mpmc_queue(&fastcgi_handler_cxt, ctx);
}

int proxy_handle(client_ctx_t *ctx) {
    return mpmc_queue(&proxy_handler_ctx, ctx);
}
