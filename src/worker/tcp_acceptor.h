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

int tcp_acceptor_init(int n_workers, int buf_size);

int tcp_accept(client_ctx_t *ctx);

void tcp_acceptor_stop(void);

void tcp_acceptor_destroy(void);

#endif //SESIMOS_TCP_ACCEPTOR_H
