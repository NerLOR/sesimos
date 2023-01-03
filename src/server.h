/**
 * sesimos - secure, simple, modern web server
 * @brief Main executable (header file)
 * @file src/server.h
 * @author Lorenz Stechauner
 * @date 2020-12-03
 */

#ifndef SESIMOS_SERVER_H
#define SESIMOS_SERVER_H

#include "worker/func.h"

#define NUM_SOCKETS 2
#define LISTEN_BACKLOG 16
#define REQ_PER_CONNECTION 200
#define CLIENT_TIMEOUT 3600
#define SERVER_TIMEOUT_INIT 4
#define SERVER_TIMEOUT 3600

#define CNX_HANDLER_WORKERS 8
#define REQ_HANDLER_WORKERS 16

void server_free_client(client_ctx_t *ctx);

#endif //SESIMOS_SERVER_H
