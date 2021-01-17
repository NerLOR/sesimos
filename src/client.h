/**
 * Necronda Web Server
 * Client connection and request handlers (header file)
 * src/client.h
 * Lorenz Stechauner, 2021-01-17
 */

#ifndef NECRONDA_SERVER_CLIENT_H
#define NECRONDA_SERVER_CLIENT_H

#include "necronda-server.h"
#include "utils.h"
#include "uri.h"
#include "http.h"
#include "fastcgi.h"


int server_keep_alive = 1;
char *log_client_prefix, *log_conn_prefix, *log_req_prefix, *client_geoip;

struct timeval client_timeout = {.tv_sec = CLIENT_TIMEOUT, .tv_usec = 0};

#endif //NECRONDA_SERVER_CLIENT_H
