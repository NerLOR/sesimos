/**
 * sesimos - secure, simple, modern web server
 * @brief Main executable (header file)
 * @file src/server.h
 * @author Lorenz Stechauner
 * @date 2020-12-03
 */

#ifndef SESIMOS_SERVER_H
#define SESIMOS_SERVER_H

#include <sys/time.h>
#include <maxminddb.h>
#include <signal.h>

#define NUM_SOCKETS 2
#define MAX_CHILDREN 64
#define LISTEN_BACKLOG 16
#define REQ_PER_CONNECTION 200
#define CLIENT_TIMEOUT 3600
#define SERVER_TIMEOUT_INIT 4
#define SERVER_TIMEOUT 3600
#define MAX_CLIENTS 4096

#define CNX_HANDLER_WORKERS 8
#define REQ_HANDLER_WORKERS 16

extern volatile sig_atomic_t alive;

#endif //SESIMOS_SERVER_H
