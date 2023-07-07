/**
 * sesimos - secure, simple, modern web server
 * @brief Worker interface (header file)
 * @file src/workers.h
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#ifndef SESIMOS_WORKERS_H
#define SESIMOS_WORKERS_H

#include "worker/func.h"

int workers_init(void);

void workers_stop(void);

void workers_destroy(void);

int tcp_accept(client_ctx_t *ctx);

int handle_request(client_ctx_t *ctx);

int local_handle(client_ctx_t *ctx);

int fastcgi_handle(client_ctx_t *ctx);

int fastcgi_handle_frame(fastcgi_ctx_t *ctx);

int proxy_handle(client_ctx_t *ctx);

int proxy_peer_handle(proxy_ctx_t *ctx);

int ws_handle_frame(ws_ctx_t *ctx);

int handle_chunk(chunk_ctx_t *ctx);

#endif //SESIMOS_WORKERS_H
