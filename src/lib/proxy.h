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
#define PROXY_COMPRESS_GZ 2
#define PROXY_COMPRESS_BR 4
#define PROXY_COMPRESS 6

#ifndef SERVER_NAME
#   define SERVER_NAME "reverse proxy"
#endif

#define PROXY_ARRAY_SIZE (MAX_PROXY_CNX_PER_HOST * sizeof(proxy_ctx_t))

#include "http.h"
#include "config.h"

typedef struct {
    unsigned char initialized:1;
    unsigned char in_use:1;
    sock proxy;
    char *host;
} proxy_ctx_t;

int proxy_preload(void);

void proxy_unload(void);

int proxy_request_header(http_req *req, sock *sock);

int proxy_response_header(http_req *req, http_res *res, host_config_t *conf);

proxy_ctx_t *proxy_init(http_req *req, http_res *res, http_status_ctx *ctx, host_config_t *conf, sock *client, http_status *custom_status, char *err_msg);

int proxy_send(proxy_ctx_t *proxy, sock *client, unsigned long len_to_send, int flags);

int proxy_dump(proxy_ctx_t *proxy, char *buf, long len);

#endif //SESIMOS_PROXY_H
