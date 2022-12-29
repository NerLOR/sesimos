/**
 * sesimos - secure, simple, modern web server
 * @brief Client request handler
 * @file src/worker/request_handler.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "../defs.h"
#include "func.h"
#include "../workers.h"
#include "../lib/mpmc.h"
#include "../logger.h"
#include "../lib/utils.h"

#include <string.h>
#include <openssl/err.h>
#include <arpa/inet.h>

static int request_handler(client_ctx_t *ctx);

void request_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%*s]%s", INET6_ADDRSTRLEN, ctx->s_addr, ctx->log_prefix);

    switch (request_handler(ctx)) {
        case 0: respond(ctx); break;
        case 1: local_handle(ctx); break;
        case 2: proxy_handle(ctx); break;
        default: tcp_close(ctx); break;
    }
}

static int request_handler(client_ctx_t *ctx) {
    sock *client = &ctx->socket;
    char *err_msg = ctx->err_msg;

    long ret;
    char buf0[1024], buf1[1024];

    err_msg[0] = 0;

    ctx->use_fastcgi = 0;
    ctx->use_proxy = 0;

    http_res *res = &ctx->res;
    res->status = http_get_status(501);
    res->hdr.field_num = 0;
    res->hdr.last_field_num = -1;
    sprintf(res->version, "1.1");

    http_status_ctx *status = &ctx->status;
    status->status = 0;
    status->origin = NONE;
    status->ws_key = NULL;

    ctx->fcgi_cnx.socket = 0;
    ctx->fcgi_cnx.req_id = 0;
    ctx->fcgi_cnx.r_addr = ctx->addr;
    ctx->fcgi_cnx.r_host = (ctx->host[0] != 0) ? ctx->host : NULL;

    clock_gettime(CLOCK_MONOTONIC, &ctx->begin);

    //ret = sock_poll_read(&client, NULL, NULL, 1, NULL, NULL, CLIENT_TIMEOUT * 1000);

    http_add_header_field(&res->hdr, "Date", http_get_date(buf0, sizeof(buf0)));
    http_add_header_field(&res->hdr, "Server", SERVER_STR);
    /*if (ret <= 0) {
        if (errno != 0) return 0;

        ctx->c_keep_alive = 0;
        res->status = http_get_status(408);
        return 0;
    }*/
    //clock_gettime(CLOCK_MONOTONIC, &begin);

    http_req *req = &ctx->req;
    ret = http_receive_request(client, req);
    if (ret != 0) {
        ctx->c_keep_alive = 0;
        if (ret < 0) {
            return -1;
        } else if (ret == 1) {
            sprintf(err_msg, "Unable to parse http header: Invalid header format.");
        } else if (ret == 2) {
            sprintf(err_msg, "Unable to parse http header: Invalid method.");
        } else if (ret == 3) {
            sprintf(err_msg, "Unable to parse http header: Invalid version.");
        } else if (ret == 4) {
            sprintf(err_msg, "Unable to parse http header: Header contains illegal characters.");
        } else if (ret == 5) {
            sprintf(err_msg, "Unable to parse http header: End of header not found.");
        }
        res->status = http_get_status(400);
        return 0;
    }

    const char *hdr_connection = http_get_header_field(&req->hdr, "Connection");
    ctx->c_keep_alive = (hdr_connection != NULL && (strstr(hdr_connection, "keep-alive") != NULL || strstr(hdr_connection, "Keep-Alive") != NULL));
    const char *host_ptr = http_get_header_field(&req->hdr, "Host");
    if (host_ptr != NULL && strlen(host_ptr) > 255) {
        ctx->req_host[0] = 0;
        res->status = http_get_status(400);
        sprintf(err_msg, "Host header field is too long.");
        return 0;
    } else if (host_ptr == NULL || strchr(host_ptr, '/') != NULL) {
        if (strchr(ctx->addr, ':') == NULL) {
            strcpy(ctx->req_host, ctx->addr);
        } else {
            sprintf(ctx->req_host, "[%s]", ctx->addr);
        }
        res->status = http_get_status(400);
        sprintf(err_msg, "The client provided no or an invalid Host header field.");
        return 0;
    } else {
        strcpy(ctx->req_host, host_ptr);
    }

    logger_set_prefix("[%s%*s%s]%s", BLD_STR, INET6_ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);
    info(BLD_STR "%s %s", req->method, req->uri);

    ctx->conf = get_host_config(ctx->req_host);
    if (ctx->conf == NULL) {
        info("Unknown host, redirecting to default");
        res->status = http_get_status(307);
        sprintf(buf0, "https://%s%s", DEFAULT_HOST, req->uri);
        http_add_header_field(&res->hdr, "Location", buf0);
        return 0;
    }

    http_uri *uri = &ctx->uri;
    unsigned char dir_mode = (ctx->conf->type == CONFIG_TYPE_LOCAL ? ctx->conf->local.dir_mode : URI_DIR_MODE_NO_VALIDATION);
    ret = uri_init(uri, ctx->conf->local.webroot, req->uri, dir_mode);
    if (ret != 0) {
        if (ret == 1) {
            sprintf(err_msg, "Invalid URI: has to start with slash.");
            res->status = http_get_status(400);
        } else if (ret == 2) {
            sprintf(err_msg, "Invalid URI: contains relative path change (/../).");
            res->status = http_get_status(400);
        } else if (ret == 3) {
            sprintf(err_msg, "The specified webroot directory does not exist.");
            res->status = http_get_status(404);
        } else {
            res->status = http_get_status(500);
        }
        return 0;
    }

    if (dir_mode != URI_DIR_MODE_NO_VALIDATION) {
        ssize_t size = sizeof(buf0);
        url_decode(req->uri, buf0, &size);
        int change_proto = strncmp(uri->uri, "/.well-known/", 13) != 0 && !client->enc;
        if (strcmp(uri->uri, buf0) != 0 || change_proto) {
            res->status = http_get_status(308);
            size = url_encode(uri->uri, strlen(uri->uri), buf0, sizeof(buf0));
            if (change_proto) {
                int p_len = snprintf(buf1, sizeof(buf1), "https://%s%s", ctx->req_host, buf0);
                if (p_len < 0 || p_len >= sizeof(buf1)) {
                    res->status = http_get_status(500);
                    error("Header field 'Location' too long");
                    return 0;
                }
                http_add_header_field(&res->hdr, "Location", buf1);
            } else {
                http_add_header_field(&res->hdr, "Location", buf0);
            }
            return 0;
        }
    } else if (!client->enc) {
        res->status = http_get_status(308);
        sprintf(buf0, "https://%s%s", ctx->req_host, req->uri);
        http_add_header_field(&res->hdr, "Location", buf0);
        return 0;
    }

    if (ctx->conf->type == CONFIG_TYPE_LOCAL) {
        return 1;
    } else if (ctx->conf->type == CONFIG_TYPE_REVERSE_PROXY) {
        return 2;
    } else {
        error("Unknown host type: %i", ctx->conf->type);
        res->status = http_get_status(501);
    }

    return 0;
}
