/**
 * sesimos - secure, simple, modern web server
 * @brief TCP closer (header file)
 * @file src/worker/tcp_closer.h
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#ifndef SESIMOS_TCP_CLOSER_H
#define SESIMOS_TCP_CLOSER_H

#include "../server.h"

void tcp_closer_func(client_ctx_t *ctx);

#endif //SESIMOS_TCP_CLOSER_H
