/**
 * sesimos - secure, simple, modern web server
 * @brief TCP acceptor (header file)
 * @file src/worker/tcp_acceptor.h
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#ifndef SESIMOS_TCP_ACCEPTOR_H
#define SESIMOS_TCP_ACCEPTOR_H

#include "../server.h"

void tcp_acceptor_func(client_ctx_t *ctx);

#endif //SESIMOS_TCP_ACCEPTOR_H
