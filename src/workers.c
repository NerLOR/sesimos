/**
 * sesimos - secure, simple, modern web server
 * @brief Worker interface
 * @file src/workers.c
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#include "workers.h"
#include "lib/mpmc.h"

#include "worker/tcp_acceptor.h"
#include "worker/tcp_closer.h"
#include "worker/responder.h"
#include "worker/request_handler.h"
#include "worker/fastcgi_handler.h"

static mpmc_t tcp_acceptor_ctx, tcp_closer_ctx, request_handler_ctx, responder_ctx, fastcgi_handler_cxt;

int workers_init(void) {
    mpmc_init(&tcp_acceptor_ctx,     8, 64, (void (*)(void *)) tcp_acceptor_func,    "tcp_a");
    mpmc_init(&tcp_closer_ctx,       8, 64, (void (*)(void *)) tcp_closer_func,      "tcp_c");
    mpmc_init(&request_handler_ctx, 16, 64, (void (*)(void *)) request_handler_func, "req");
    mpmc_init(&responder_ctx,       16, 64, (void (*)(void *)) responder_func,       "res");
    mpmc_init(&fastcgi_handler_cxt, 16, 64, (void (*)(void *)) fastcgi_handler_func, "fcgi");
    return -1;
}

void workers_stop(void) {
    mpmc_stop(&tcp_acceptor_ctx);
    mpmc_stop(&request_handler_ctx);
    mpmc_stop(&responder_ctx);
    mpmc_stop(&tcp_closer_ctx);
}

void workers_destroy(void) {
    mpmc_destroy(&tcp_acceptor_ctx);
    mpmc_destroy(&request_handler_ctx);
    mpmc_destroy(&responder_ctx);
    mpmc_destroy(&tcp_closer_ctx);
}

int tcp_accept(client_ctx_t *ctx) {
    return mpmc_queue(&tcp_acceptor_ctx, ctx);
}

int tcp_close(client_ctx_t *ctx) {
    return mpmc_queue(&tcp_closer_ctx, ctx);
}

int handle_request(client_ctx_t *ctx) {
    return mpmc_queue(&request_handler_ctx, ctx);
}

int respond(client_ctx_t *ctx) {
    return mpmc_queue(&responder_ctx, ctx);
}

int fastcgi_handle(client_ctx_t *ctx) {
    return mpmc_queue(&fastcgi_handler_cxt, ctx);
}

