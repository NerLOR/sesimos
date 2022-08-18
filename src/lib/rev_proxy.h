/**
 * sesimos - secure, simple, modern web server
 * Reverse proxy (header file)
 * src/lib/rev_proxy.h
 * Lorenz Stechauner, 2021-01-07
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

extern sock rev_proxy;

int rev_proxy_preload();

int rev_proxy_request_header(http_req *req, int enc);

int rev_proxy_response_header(http_req *req, http_res *res, host_config *conf);

int rev_proxy_init(http_req *req, http_res *res, http_status_ctx *ctx, host_config *conf, sock *client,
                   http_status *custom_status, char *err_msg);

int rev_proxy_send(sock *client, unsigned long len_to_send, int flags);

int rev_proxy_dump(char *buf, long len);

#endif //SESIMOS_REV_PROXY_H
