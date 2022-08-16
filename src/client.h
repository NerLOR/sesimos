/**
 * Necronda Web Server
 * Client connection and request handlers
 * src/client.h
 * Lorenz Stechauner, 2022-08-16
 */

#ifndef NECRONDA_SERVER_NECRONDA_CLIENT_H
#define NECRONDA_SERVER_NECRONDA_CLIENT_H

#include "lib/config.h"
#include "lib/sock.h"

#include <arpa/inet.h>

host_config *get_host_config(const char *host);

int client_handler(sock *client, unsigned long client_num, struct sockaddr_in6 *client_addr);

#endif //NECRONDA_SERVER_NECRONDA_CLIENT_H
