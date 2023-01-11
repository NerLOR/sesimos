/**
 * sesimos - secure, simple, modern web server
 * @brief Local filesystem handler
 * @file src/worker/local_handler.c
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#include "func.h"
#include "../logger.h"
#include "../lib/utils.h"
#include "../lib/compress.h"
#include "../workers.h"
#include "../lib/list.h"

#include <string.h>
#include <errno.h>

static int local_handler(client_ctx_t *ctx);

void local_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%s%*s%s]%s", BLD_STR, INET6_ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);

    switch (local_handler(ctx)) {
        case 0:
            respond(ctx);
            request_complete(ctx);
            handle_request(ctx);
            break;
        case 1:
            fastcgi_handle(ctx);
            break;
        default:
            tcp_close(ctx);
            break;
    }
}

static int range_handler(client_ctx_t *ctx) {
    char buf[64];
    long num0, num1, num2;
    char *ptr;
    int mode;
    const char *range = http_get_header_field(&ctx->req.hdr, "Range");

    if (strcontains(range, ","))
        return -1;

    ctx->file = fopen(ctx->uri.filename, "rb");

    if (strstarts(range, "bytes=")) {
        mode = 0;
        range += 6;
        num0 = fsize(ctx->file), num1 = 0, num2 = num0 - 1;
        sprintf(buf, "bytes */%li", num0);
    } else if (strstarts(range, "lines=") && mime_is_text(ctx->uri.meta->type)) {
        mode = 1;
        range += 6;
        num0 = flines(ctx->file), num1 = 1, num2 = num0;
        sprintf(buf, "lines */%li", num0);
    } else {
        return -1;
    }

    http_add_header_field(&ctx->res.hdr, "Content-Range", buf);

    if ((ptr = strchr(range, '-')) == NULL)
        return -1;

    if (num0 == 0) {
        ctx->content_length = 0;
        return 0;
    }

    if (ptr[1] != 0) num2 = (long) strtoul(ptr + 1, NULL, 10);
    if (ptr != range) {
        num1 = (long) strtoul(range, NULL, 10);
    } else {
        if (mode == 0) {
            num1 = num0 - num2 - 1;
            num2 = num0 - 1;
        } else if (mode == 1) {
            num1 = num0 - num2 + 1;
            num2 = num0;
        }
    }

    if ((mode == 0 && (num1 >= num0 || num2 >= num0 || num1 > num2 || num1 < 0 || num2 < 0)) ||
        (mode == 1 && (num1 > num0 || num2 > num0 || num1 > num2 || num1 <= 0 || num2 <= 0)))
    {
        return -1;
    }

    sprintf(buf, "%s %li-%li/%li", (mode == 0) ? "bytes" : "lines", num1, num2, num0);
    http_remove_header_field(&ctx->res.hdr, "Content-Range", HTTP_REMOVE_ALL);
    http_add_header_field(&ctx->res.hdr, "Content-Range", buf);

    if (mode == 0) {
        fseek(ctx->file, num1, SEEK_SET);
        ctx->content_length = num2 - num1 + 1;
    } else if (mode == 1) {
        fseekl(ctx->file, num1);
        ctx->content_length = file_get_line_pos(ctx->file, num2 + 1) - file_get_line_pos(ctx->file, num1);
    }

    return 0;
}

static int local_handler(client_ctx_t *ctx) {
    http_res *res = &ctx->res;
    http_req *req = &ctx->req;
    http_uri *uri = &ctx->uri;
    char *err_msg = ctx->err_msg;

    char buf1[1024], buf2[1024];
    int accept_if_modified_since = 0;

    if (streq(req->method, "TRACE")) {
        res->status = http_get_status(200);
        http_add_header_field(&res->hdr, "Content-Type", "message/http");

        ctx->msg_buf_ptr = malloc(4096);
        ctx->msg_buf = ctx->msg_buf_ptr;
        ctx->content_length = snprintf(ctx->msg_buf, 4096 - ctx->content_length, "%s %s HTTP/%s\r\n", req->method, req->uri, req->version);
        for (int i = 0; i < list_size(req->hdr.fields); i++) {
            const http_field *f = &req->hdr.fields[i];
            ctx->content_length += snprintf(ctx->msg_buf + ctx->content_length, 4096 - ctx->content_length, "%s: %s\r\n", http_field_get_name(f), http_field_get_value(f));
        }

        return 0;
    }

    if (strstarts(uri->req_path, "/.well-known/")) {
        http_add_header_field(&res->hdr, "Access-Control-Allow-Origin", "*");
    }

    if (!strstarts(uri->req_path, "/.well-known/") && strcontains(uri->path, "/.")) {
        res->status = http_get_status(403);
        sprintf(err_msg, "Parts of this URI are hidden.");
        return 0;
    } else if (uri->filename == NULL && (int) uri->is_static && (int) uri->is_dir && strlen(uri->pathinfo) == 0) {
        res->status = http_get_status(403);
        sprintf(err_msg, "It is not allowed to list the contents of this directory.");
        return 0;
    } else if (uri->filename == NULL && (int) !uri->is_static && (int) uri->is_dir && strlen(uri->pathinfo) == 0) {
        // TODO list directory contents
        res->status = http_get_status(501);
        sprintf(err_msg, "Listing contents of an directory is currently not implemented.");
        return 0;
    } else if (uri->filename == NULL || (strlen(uri->pathinfo) > 0 && (int) uri->is_static)) {
        res->status = http_get_status(404);
        return 0;
    } else if (strlen(uri->pathinfo) != 0 && ctx->conf->local.dir_mode != URI_DIR_MODE_INFO) {
        res->status = http_get_status(404);
        return 0;
    }

    if (uri->is_static) {
        res->status = http_get_status(200);
        cache_init_uri(ctx->conf->cache, uri);

        http_add_header_field(&res->hdr, "Accept-Ranges", mime_is_text(uri->meta->type) ? "bytes, lines" : "bytes");

        if (!streq(req->method, "GET") && !streq(req->method, "HEAD")) {
            res->status = http_get_status(405);
            return 0;
        }

        if (http_get_header_field(&req->hdr, "Content-Length") != NULL || http_get_header_field(&req->hdr, "Transfer-Encoding") != NULL) {
            res->status = http_get_status(400);
            sprintf(err_msg, "A GET request must not contain a payload");
            return 0;
        }

        const char *last_modified = http_format_date(uri->meta->mtime, buf1, sizeof(buf1));
        http_add_header_field(&res->hdr, "Last-Modified", last_modified);
        sprintf(buf2, "%s; charset=%s", uri->meta->type, uri->meta->charset);
        http_add_header_field(&res->hdr, "Content-Type", buf2);

        const char *accept_encoding = http_get_header_field(&req->hdr, "Accept-Encoding");
        int enc = 0;
        if (accept_encoding != NULL) {
            if (uri->meta->filename_comp_br[0] != 0 && strcontains(accept_encoding, "br")) {
                ctx->file = fopen(uri->meta->filename_comp_br, "rb");
                if (ctx->file == NULL) {
                    cache_mark_dirty(ctx->conf->cache, uri->filename);
                    errno = 0;
                } else {
                    http_add_header_field(&res->hdr, "Content-Encoding", "br");
                    enc = COMPRESS_BR;
                }
            } else if (uri->meta->filename_comp_gz[0] != 0 && strcontains(accept_encoding, "gzip")) {
                ctx->file = fopen(uri->meta->filename_comp_gz, "rb");
                if (ctx->file == NULL) {
                    cache_mark_dirty(ctx->conf->cache, uri->filename);
                    errno = 0;
                } else {
                    http_add_header_field(&res->hdr, "Content-Encoding", "gzip");
                    enc = COMPRESS_GZ;
                }
            }
            if (enc != 0) {
                http_add_header_field(&res->hdr, "Vary", "Accept-Encoding");
            }
        }

        if (uri->meta->etag[0] != 0) {
            strcpy(buf1, uri->meta->etag);
            if (enc) {
                strcat(buf1, "-");
                strcat(buf1, (enc & COMPRESS_BR) ? "br" : (enc & COMPRESS_GZ) ? "gzip" : "");
            }
            http_add_header_field(&res->hdr, "ETag", buf1);
        }

        http_add_header_field(&res->hdr, "Cache-Control", mime_is_text(uri->meta->type) ? "public, max-age=3600" : "public, max-age=86400");

        const char *if_modified_since = http_get_header_field(&req->hdr, "If-Modified-Since");
        const char *if_none_match = http_get_header_field(&req->hdr, "If-None-Match");
        if ((if_none_match != NULL && !strcontains(if_none_match, uri->meta->etag)) ||
            (accept_if_modified_since && streq(if_modified_since, last_modified)))
        {
            res->status = http_get_status(304);
            return 0;
        }

        if (http_get_header_field(&req->hdr, "Range") != NULL) {
            if (range_handler(ctx) == 0) {
                res->status = http_get_status(206);
            } else {
                if (ctx->file) {
                    fclose(ctx->file);
                    ctx->file = NULL;
                }
                http_remove_header_field(&res->hdr, "Content-Type", HTTP_REMOVE_ALL);
                http_remove_header_field(&res->hdr, "Last-Modified", HTTP_REMOVE_ALL);
                http_remove_header_field(&res->hdr, "ETag", HTTP_REMOVE_ALL);
                http_remove_header_field(&res->hdr, "Cache-Control", HTTP_REMOVE_ALL);
                res->status = http_get_status(416);
            }
            return 0;
        }

        if (ctx->file == NULL) ctx->file = fopen(uri->filename, "rb");
        ctx->content_length = fsize(ctx->file);
    } else {
        return 1;
    }

    return 0;
}
