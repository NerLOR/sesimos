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

host_config *get_host_config(const char *host);

int client_handler(sock *client, unsigned long client_num, struct sockaddr_in6 *client_addr);

#endif //SESIMOS_CLIENT_H
