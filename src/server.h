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
#define MAX_CHILDREN 1024
#define LISTEN_BACKLOG 16
#define REQ_PER_CONNECTION 200
#define CLIENT_TIMEOUT 3600
#define SERVER_TIMEOUT_INIT 4
#define SERVER_TIMEOUT 3600

extern int sockets[NUM_SOCKETS];
extern pid_t children[MAX_CHILDREN];

extern volatile sig_atomic_t server_keep_alive;
extern struct timeval client_timeout;

#endif //SESIMOS_SERVER_H
