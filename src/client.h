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
#include "lib/geoip.h"

#include <arpa/inet.h>

typedef struct {
    char *addr;
    char *s_addr;
    char cc[3];
    char host[256];
    char geoip[GEOIP_MAX_JSON_SIZE + 1];
    char _c_addr[INET6_ADDRSTRLEN + 1];
    char _s_addr[INET6_ADDRSTRLEN + 1];
} client_ctx_t;

host_config_t *get_host_config(const char *host);

int client_handler(sock *client, unsigned long client_num);

#endif //SESIMOS_CLIENT_H
