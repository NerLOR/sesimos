/**
 * sesimos - secure, simple, modern web server
 * @brief FastCGI handler
 * @file src/worker/fastcgi_handler.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "func.h"
#include "../logger.h"
#include "../lib/utils.h"
#include "../workers.h"
#include "../lib/fastcgi.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>

static int fastcgi_handler_1(client_ctx_t *ctx, fastcgi_cnx_t **fcgi_cnx);
static int fastcgi_handler_2(client_ctx_t *ctx, fastcgi_cnx_t *fcgi_cnx);

void fastcgi_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%s%*s%s]%s", BLD_STR, ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);

    if (!ctx->chunks_transferred) {
        fastcgi_cnx_t *fcgi_cnx = NULL;
        int ret = fastcgi_handler_1(ctx, &fcgi_cnx);
        respond(ctx);
        if (ret == 0) {
            switch (fastcgi_handler_2(ctx, fcgi_cnx)) {
                case 1: return;
                case 2: break;
            }
        } else if (ctx->fcgi_ctx != NULL) {
            fastcgi_close(ctx->fcgi_ctx);
        }
    }

    request_complete(ctx);
    handle_request(ctx);
}

static int fastcgi_handler_1(client_ctx_t *ctx, fastcgi_cnx_t **fcgi_cnx) {
    http_res *res = &ctx->res;
    http_req *req = &ctx->req;
    http_uri *uri = &ctx->uri;
    sock *client = &ctx->socket;
    char *err_msg = ctx->err_msg;
    char buf[1024];

    int mode, ret;
    if (strends(uri->filename, ".php")) {
        mode = FASTCGI_BACKEND_PHP;
    } else {
        res->status = http_get_status(500);
        error("Invalid FastCGI extension: %s", uri->filename);
        return 3;
    }

    fastcgi_cnx_t fcgi_cnx_buf;
    sock_init(&fcgi_cnx_buf.socket, -1, 0);
    fcgi_cnx_buf.req_id = 0;
    fcgi_cnx_buf.r_addr = ctx->socket.addr;
    fcgi_cnx_buf.r_host = (ctx->host[0] != 0) ? ctx->host : NULL;

    struct stat statbuf;
    stat(uri->filename, &statbuf);
    char *last_modified = http_format_date(statbuf.st_mtime, buf, sizeof(buf));
    http_add_header_field(&res->hdr, "Last-Modified", last_modified);

    res->status = http_get_status(200);
    if (fastcgi_init(&fcgi_cnx_buf, mode, ctx->req_num, client, req, uri) != 0) {
        fastcgi_close_cnx(&fcgi_cnx_buf);
        res->status = http_get_status(503);
        sprintf(err_msg, "Unable to communicate with FastCGI socket.");
        return 3;
    }

    (*fcgi_cnx) = &fcgi_cnx_buf;
    fastcgi_handle_connection(ctx, fcgi_cnx);

    const char *client_content_length = http_get_header_field(&req->hdr, "Content-Length");
    const char *client_transfer_encoding = http_get_header_field(&req->hdr, "Transfer-Encoding");
    if (client_content_length != NULL) {
        unsigned long client_content_len = strtoul(client_content_length, NULL, 10);
        ret = fastcgi_receive(*fcgi_cnx, client, client_content_len);
    } else if (strcontains(client_transfer_encoding, "chunked")) {
        ret = fastcgi_receive_chunked(*fcgi_cnx, client);
    } else {
        ret = 0;
    }
    if (ret != 0) {
        if (ret < 0) {
            return -1;
        } else {
            sprintf(err_msg, "Unable to communicate with FastCGI socket.");
        }
        res->status = http_get_status(502);
        return 2;
    }
    fastcgi_close_stdin(*fcgi_cnx);

    if ((ret = fastcgi_header(*fcgi_cnx, res, err_msg)) != 0) {
        if (ret == -1) res->status = http_get_status(502);
        return ret;
    }

    const char *status_hdr = http_get_header_field(&res->hdr, "Status");
    if (status_hdr != NULL) {
        int status_code = (int) strtoul(status_hdr, NULL, 10);
        res->status = http_get_status(status_code);
        http_remove_header_field(&res->hdr, "Status", HTTP_REMOVE_ALL);
        if (res->status == NULL && status_code >= 100 && status_code <= 999) {
            ctx->custom_status.code = status_code;
            ctx->custom_status.type = 0;
            strcpy(ctx->custom_status.msg, status_hdr + 4);
            res->status = &ctx->custom_status;
        } else if (res->status == NULL) {
            res->status = http_get_status(500);
            sprintf(err_msg, "The status_hdr code was set to an invalid or unknown value.");
            return 2;
        }
    }

    const char *content_length_f = http_get_header_field(&res->hdr, "Content-Length");
    ctx->content_length = (content_length_f == NULL) ? -1 : strtol(content_length_f, NULL, 10);

    const char *content_type = http_get_header_field(&res->hdr, "Content-Type");
    const char *content_encoding = http_get_header_field(&res->hdr, "Content-Encoding");
    if (content_encoding == NULL &&
        content_type != NULL &&
        strstarts(content_type, "text/html") &&
        ctx->content_length != -1 &&
        ctx->content_length <= sizeof(ctx->msg_content) - 1)
    {
        fastcgi_dump(*fcgi_cnx, ctx->msg_content, sizeof(ctx->msg_content));
        return 1;
    }

    ctx->use_fastcgi = 1;
    ctx->content_length = -1;

    if (http_get_header_field(&res->hdr, "Content-Length") == NULL) {
        http_add_header_field(&res->hdr, "Transfer-Encoding", "chunked");
    }

    return 0;
}

static void fastcgi_next_cb(chunk_ctx_t *ctx) {
    if(ctx->client->fcgi_ctx) {
        fastcgi_close(ctx->client->fcgi_ctx);
        ctx->client->fcgi_ctx = NULL;
    }

    fastcgi_handle(ctx->client);
}

static void fastcgi_error_cb(chunk_ctx_t *ctx) {
    if (ctx->client->chunks_transferred)
        return;

    logger_set_prefix("[%s%*s%s]%s", BLD_STR, ADDRSTRLEN, ctx->client->req_host, CLR_STR, ctx->client->log_prefix);

    // FIXME segfault on error_cb
    warning("Closing connection due to FastCGI error");
    if(ctx->client->fcgi_ctx) {
        fastcgi_close(ctx->client->fcgi_ctx);
        ctx->client->fcgi_ctx = NULL;
    }

    tcp_close(ctx->client);

    errno = 0;
}

static int fastcgi_handler_2(client_ctx_t *ctx, fastcgi_cnx_t *fcgi_cnx) {
    int chunked = strcontains(http_get_header_field(&ctx->res.hdr, "Transfer-Encoding"), "chunked");

    if (chunked) {
        handle_chunks(ctx, &fcgi_cnx->out, SOCK_CHUNKED, fastcgi_next_cb, fastcgi_error_cb);
        return 1;
    } else {
        fastcgi_send(fcgi_cnx, &ctx->socket);
        fastcgi_close(ctx->fcgi_ctx);
        ctx->fcgi_ctx = NULL;
        fastcgi_handle(ctx);
        return 2;
    }
}
