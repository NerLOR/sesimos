/**
 * sesimos - secure, simple, modern web server
 * @brief Main executable (header file)
 * @file src/server.h
 * @author Lorenz Stechauner
 * @date 2020-12-03
 */

#ifndef SESIMOS_SERVER_H
#define SESIMOS_SERVER_H

#include "lib/sock.h"
#include "lib/http.h"
#include "lib/uri.h"
#include "lib/config.h"
#include "lib/fastcgi.h"

#include <sys/time.h>
#include <maxminddb.h>
#include <signal.h>
#include <arpa/inet.h>

#define NUM_SOCKETS 2
#define LISTEN_BACKLOG 16
#define REQ_PER_CONNECTION 200
#define CLIENT_TIMEOUT 3600
#define SERVER_TIMEOUT_INIT 4
#define SERVER_TIMEOUT 3600
#define MAX_CLIENTS 4096

#define CNX_HANDLER_WORKERS 8
#define REQ_HANDLER_WORKERS 16

typedef struct {
    sock socket;
    int req_num;
    char *addr, *s_addr;
    unsigned char in_use: 1, s_keep_alive:1, c_keep_alive:1;
    char cc[3], host[256];
    char req_host[256], err_msg[256];
    char log_prefix[512];
    char _c_addr[INET6_ADDRSTRLEN + 1], _s_addr[INET6_ADDRSTRLEN + 1];
    struct timespec begin, end;
    http_req req;
    http_res res;
    http_uri uri;
    http_status_ctx status;
    http_status custom_status;
    int use_fastcgi, use_proxy;
    host_config_t *conf;
    FILE *file;
    long content_length;
    fastcgi_cnx_t fcgi_cnx;
    char msg_buf[8192], msg_content[1024];
} client_ctx_t;

extern volatile sig_atomic_t server_alive;


#endif //SESIMOS_SERVER_H
