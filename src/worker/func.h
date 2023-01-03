/**
 * sesimos - secure, simple, modern web server
 * @brief Worker function header file
 * @file src/worker/func.h
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#ifndef SESIMOS_FUNC_H
#define SESIMOS_FUNC_H

#include "../lib/sock.h"
#include "../lib/http.h"
#include "../lib/uri.h"
#include "../lib/config.h"
#include "../lib/proxy.h"

typedef struct {
    sock socket;
    int req_num;
    unsigned char in_use: 1, s_keep_alive:1, c_keep_alive:1, use_fastcgi:4, use_proxy:2, ws_close:2;
    char cc[3], host[256];
    char req_host[256], err_msg[256];
    char log_prefix[128];
    char _c_addr[INET6_ADDRSTRLEN + 1], _s_addr[INET6_ADDRSTRLEN + 1];
    long cnx_s, cnx_e, req_s, res_ts, req_e;
    http_req req;
    http_res res;
    http_uri uri;
    http_status_ctx status;
    http_status custom_status;
    host_config_t *conf;
    FILE *file;
    long content_length;
    char *msg_buf, *msg_buf_ptr, msg_content[1024];
    proxy_ctx_t *proxy;
} client_ctx_t;

typedef struct {
    client_ctx_t *client;
    sock *s1, *s2, *s, *r;
} ws_ctx_t;

void tcp_acceptor_func(client_ctx_t *ctx);

void request_handler_func(client_ctx_t *ctx);

void local_handler_func(client_ctx_t *ctx);

void fastcgi_handler_func(client_ctx_t *ctx);

void proxy_handler_func(client_ctx_t *ctx);

void ws_frame_handler_func(ws_ctx_t *ctx);

int respond(client_ctx_t *ctx);

void request_complete(client_ctx_t *ctx);

void tcp_close(client_ctx_t *ctx);

void proxy_close(proxy_ctx_t *ctx);

#endif //SESIMOS_FUNC_H
