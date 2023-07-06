/**
 * sesimos - secure, simple, modern web server
 * @brief Reverse proxy (header file)
 * @file src/lib/proxy.h
 * @author Lorenz Stechauner
 * @date 2021-01-07
 */

#ifndef SESIMOS_PROXY_H
#define SESIMOS_PROXY_H

#define PROXY_CHUNKED 1

#ifndef SERVER_NAME
#   define SERVER_NAME "reverse proxy"
#endif

#include "http.h"
#include "config.h"

typedef struct {
    volatile unsigned char initialized:1, in_use:1;
    sock proxy;
    long cnx_s, cnx_e;
    long http_timeout;
    char *host;
    void *client;
} proxy_ctx_t;

int proxy_preload(void);

void proxy_unload(void);

void proxy_close_all(void);

proxy_ctx_t *proxy_get_by_conf(host_config_t *conf);

void proxy_unlock_ctx(proxy_ctx_t *ctx);

int proxy_request_header(http_req *req, sock *sock);

int proxy_response_header(http_req *req, http_res *res, host_config_t *conf);

int proxy_init(proxy_ctx_t **proxy, http_req *req, http_res *res, http_status_ctx *ctx, host_config_t *conf, sock *client, http_status *custom_status, char *err_msg);

int proxy_send(proxy_ctx_t *proxy, sock *client, unsigned long len_to_send, int flags);

int proxy_dump(proxy_ctx_t *proxy, char *buf, long len);

void proxy_close(proxy_ctx_t *ctx);

#endif //SESIMOS_PROXY_H
