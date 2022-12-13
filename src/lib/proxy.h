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
#   define SERVER_NAME "revproxy"
#endif

#include "http.h"
#include "config.h"
#include "../client.h"

extern sock proxy;

int proxy_preload(void);

int proxy_request_header(http_req *req, int enc, client_ctx_t *ctx);

int proxy_response_header(http_req *req, http_res *res, host_config *conf);

int proxy_init(http_req *req, http_res *res, http_status_ctx *ctx, host_config *conf, sock *client, client_ctx_t *cctx, http_status *custom_status, char *err_msg);

int proxy_send(sock *client, unsigned long len_to_send, int flags);

int proxy_dump(char *buf, long len);

#endif //SESIMOS_PROXY_H
