/**
 * Necronda Web Server
 * Reverse proxy (header file)
 * src/lib/rev_proxy.h
 * Lorenz Stechauner, 2021-01-07
 */

#ifndef NECRONDA_SERVER_REV_PROXY_H
#define NECRONDA_SERVER_REV_PROXY_H

#include "http.h"
#include "config.h"

extern sock rev_proxy;

int rev_proxy_preload();

int rev_proxy_request_header(http_req *req, int enc);

int rev_proxy_response_header(http_req *req, http_res *res);

int rev_proxy_init(http_req *req, http_res *res, host_config *conf, sock *client, http_status *custom_status,
                   char *err_msg);

int rev_proxy_send(sock *client, int chunked, unsigned long len_to_send);

#endif //NECRONDA_SERVER_REV_PROXY_H
