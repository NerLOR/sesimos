/**
 * Necronda Web Server
 * Main executable (header file)
 * src/necronda-server.h
 * Lorenz Stechauner, 2020-12-03
 */

#ifndef NECRONDA_SERVER_NECRONDA_SERVER_H
#define NECRONDA_SERVER_NECRONDA_SERVER_H

#include <sys/time.h>
#include <maxminddb.h>

#define NUM_SOCKETS 2
#define MAX_CHILDREN 1024
#define MAX_MMDB 3
#define LISTEN_BACKLOG 16
#define REQ_PER_CONNECTION 200
#define CLIENT_TIMEOUT 3600
#define SERVER_TIMEOUT_INIT 4
#define SERVER_TIMEOUT 3600

#define CHUNK_SIZE 8192

extern int sockets[NUM_SOCKETS];
extern pid_t children[MAX_CHILDREN];
extern MMDB_s mmdbs[MAX_MMDB];

extern int server_keep_alive;
extern char *log_client_prefix, *log_conn_prefix, *log_req_prefix, *client_geoip;
extern char *client_addr_str, *client_addr_str_ptr, *server_addr_str, *server_addr_str_ptr, *client_host_str;
extern struct timeval client_timeout;

#endif //NECRONDA_SERVER_NECRONDA_SERVER_H
