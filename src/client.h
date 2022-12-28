/**
 * sesimos - secure, simple, modern web server
 * @brief Client connection and request handlers (header file)
 * @file src/client.h
 * @author Lorenz Stechauner
 * @date 2022-08-16
 */

#ifndef SESIMOS_CLIENT_H
#define SESIMOS_CLIENT_H

#include "lib/config.h"
#include "lib/sock.h"

#include <arpa/inet.h>

typedef struct {
    sock socket;
    char *addr;
    char *s_addr;
    unsigned char s_keep_alive:1;
    unsigned char c_keep_alive:1;
    char cc[3];
    char host[256];
    char _c_addr[INET6_ADDRSTRLEN + 1];
    char _s_addr[INET6_ADDRSTRLEN + 1];
} client_ctx_t;

host_config_t *get_host_config(const char *host);

void *client_handler(client_ctx_t *client);

#endif //SESIMOS_CLIENT_H
