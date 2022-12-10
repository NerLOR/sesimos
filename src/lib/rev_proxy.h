/**
 * sesimos - secure, simple, modern web server
 * @brief Reverse proxy (header file)
 * @file src/lib/rev_proxy.h
 * @author Lorenz Stechauner
 * @date 2021-01-07
 */

#ifndef SESIMOS_REV_PROXY_H
#define SESIMOS_REV_PROXY_H

#define REV_PROXY_CHUNKED 1
#define REV_PROXY_COMPRESS_GZ 2
#define REV_PROXY_COMPRESS_BR 4
#define REV_PROXY_COMPRESS 6

#ifndef SERVER_NAME
#   define SERVER_NAME "revproxy"
#endif

#include "http.h"
#include "config.h"
#include "../client.h"

extern sock rev_proxy;

int rev_proxy_preload(void);

int rev_proxy_request_header(http_req *req, int enc, client_ctx_t *ctx);

int rev_proxy_response_header(http_req *req, http_res *res, host_config *conf);

int rev_proxy_init(http_req *req, http_res *res, http_status_ctx *ctx, host_config *conf, sock *client, client_ctx_t *cctx, http_status *custom_status, char *err_msg);

int rev_proxy_send(sock *client, unsigned long len_to_send, int flags);

int rev_proxy_dump(char *buf, long len);

#endif //SESIMOS_REV_PROXY_H
