/**
 * Necronda Web Server
 * Client connection and request handlers (header file)
 * src/client.h
 * Lorenz Stechauner, 2021-01-17
 */

#ifndef NECRONDA_SERVER_CLIENT_H
#define NECRONDA_SERVER_CLIENT_H

#include <sys/time.h>

extern int server_keep_alive;
extern char *log_client_prefix, *log_conn_prefix, *log_req_prefix, *client_geoip;
extern char *client_addr_str, *client_addr_str_ptr, *server_addr_str, *server_addr_str_ptr, *client_host_str;
extern struct timeval client_timeout;

#endif //NECRONDA_SERVER_CLIENT_H
