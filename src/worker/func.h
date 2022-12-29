/**
 * sesimos - secure, simple, modern web server
 * @brief Worker function header file
 * @file src/worker/func.h
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#ifndef SESIMOS_FUNC_H
#define SESIMOS_FUNC_H

#include "../server.h"

void tcp_acceptor_func(client_ctx_t *ctx);

void tcp_closer_func(client_ctx_t *ctx);

void request_handler_func(client_ctx_t *ctx);

void responder_func(client_ctx_t *ctx);

void fastcgi_handler_func(client_ctx_t *ctx);

#endif //SESIMOS_FUNC_H
