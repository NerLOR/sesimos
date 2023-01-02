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
#include "../lib/compress.h"
#include "../workers.h"
#include "../lib/fastcgi.h"

#include <string.h>
#include <errno.h>

static int fastcgi_handler_1(client_ctx_t *ctx, fastcgi_cnx_t *fcgi_cnx);
static int fastcgi_handler_2(client_ctx_t *ctx, fastcgi_cnx_t *fcgi_cnx);

void fastcgi_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%s%*s%s]%s", BLD_STR, INET6_ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);

    fastcgi_cnx_t fcgi_cnx;
    int ret = fastcgi_handler_1(ctx, &fcgi_cnx);
    respond(ctx);
    if (ret == 0) fastcgi_handler_2(ctx, &fcgi_cnx);
    request_complete(ctx);

    handle_request(ctx);
}

static int fastcgi_handler_1(client_ctx_t *ctx, fastcgi_cnx_t *fcgi_cnx) {
    http_res *res = &ctx->res;
    http_req *req = &ctx->req;
    http_uri *uri = &ctx->uri;
    sock *client = &ctx->socket;
    char *err_msg = ctx->err_msg;

    fcgi_cnx->socket = 0;
    fcgi_cnx->req_id = 0;
    fcgi_cnx->r_addr = ctx->socket.addr;
    fcgi_cnx->r_host = (ctx->host[0] != 0) ? ctx->host : NULL;

    char buf[1024];

    int mode, ret;
    if (strcmp(uri->filename + strlen(uri->filename) - 4, ".ncr") == 0) {
        mode = FASTCGI_SESIMOS;
    } else if (strcmp(uri->filename + strlen(uri->filename) - 4, ".php") == 0) {
        mode = FASTCGI_PHP;
    } else {
        res->status = http_get_status(500);
        error("Invalid FastCGI extension: %s", uri->filename);
        return 0;
    }

    struct stat statbuf;
    stat(uri->filename, &statbuf);
    char *last_modified = http_format_date(statbuf.st_mtime, buf, sizeof(buf));
    http_add_header_field(&res->hdr, "Last-Modified", last_modified);

    res->status = http_get_status(200);
    if (fastcgi_init(fcgi_cnx, mode, 0 /* TODO */, ctx->req_num, client, req, uri) != 0) {
        res->status = http_get_status(503);
        sprintf(err_msg, "Unable to communicate with FastCGI socket.");
        return 2;
    }

    const char *client_content_length = http_get_header_field(&req->hdr, "Content-Length");
    const char *client_transfer_encoding = http_get_header_field(&req->hdr, "Transfer-Encoding");
    if (client_content_length != NULL) {
        unsigned long client_content_len = strtoul(client_content_length, NULL, 10);
        ret = fastcgi_receive(fcgi_cnx, client, client_content_len);
    } else if (client_transfer_encoding != NULL && strstr(client_transfer_encoding, "chunked") != NULL) {
        ret = fastcgi_receive_chunked(fcgi_cnx, client);
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
    fastcgi_close_stdin(fcgi_cnx);

    ret = fastcgi_header(fcgi_cnx, res, err_msg);
    if (ret != 0) {
        return (ret < 0) ? -1 : 1;
    }

    const char *status_hdr = http_get_header_field(&res->hdr, "Status");
    if (status_hdr != NULL) {
        int status_code = (int) strtoul(status_hdr, NULL, 10);
        res->status = http_get_status(status_code);
        http_remove_header_field(&res->hdr, "Status", HTTP_REMOVE_ALL);
        if (res->status == NULL && status_code >= 100 && status_code <= 999) {
            ctx->custom_status.code = status_code;
            strcpy(ctx->custom_status.type, "");
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
        strncmp(content_type, "text/html", 9) == 0 &&
        ctx->content_length != -1 &&
        ctx->content_length <= sizeof(ctx->msg_content) - 1)
    {
        fastcgi_dump(fcgi_cnx, ctx->msg_content, sizeof(ctx->msg_content));
        return 1;
    }

    ctx->use_fastcgi = 1;

    if (ctx->content_length != -1 && ctx->content_length < 1024000) {
        ctx->use_fastcgi |= FASTCGI_COMPRESS_HOLD;
    }

    ctx->content_length = -1;

    int http_comp = http_get_compression(req, res);
    if (http_comp & COMPRESS) {
        if (http_comp & COMPRESS_BR) {
            ctx->use_fastcgi |= FASTCGI_COMPRESS_BR;
            sprintf(buf, "br");
        } else if (http_comp & COMPRESS_GZ) {
            ctx->use_fastcgi |= FASTCGI_COMPRESS_GZ;
            sprintf(buf, "gzip");
        }
        http_add_header_field(&res->hdr, "Vary", "Accept-Encoding");
        http_add_header_field(&res->hdr, "Content-Encoding", buf);
        http_remove_header_field(&res->hdr, "Content-Length", HTTP_REMOVE_ALL);
    }

    if (http_get_header_field(&res->hdr, "Content-Length") == NULL) {
        http_add_header_field(&res->hdr, "Transfer-Encoding", "chunked");
    }

    return 0;
}

static int fastcgi_handler_2(client_ctx_t *ctx, fastcgi_cnx_t *fcgi_cnx) {
    const char *transfer_encoding = http_get_header_field(&ctx->res.hdr, "Transfer-Encoding");
    int chunked = (transfer_encoding != NULL && strstr(transfer_encoding, "chunked") != NULL);

    int flags = (chunked ? FASTCGI_CHUNKED : 0) | (ctx->use_fastcgi & (FASTCGI_COMPRESS | FASTCGI_COMPRESS_HOLD));
    int ret = fastcgi_send(fcgi_cnx, &ctx->socket, flags);
    if (ret < 0) {
        ctx->c_keep_alive = 0;
        errno = 0;
    }

    if (fcgi_cnx->socket != 0) {
        close(fcgi_cnx->socket);
        fcgi_cnx->socket = 0;
    }

    return ret;
}
