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
#include "../server.h"
#include "../lib/res.h"
#include "../lib/error.h"

#include <string.h>
#include <arpa/inet.h>
#include <errno.h>

static int request_handler(client_ctx_t *ctx);

void request_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%*s]%s", ADDRSTRLEN, ctx->socket.s_addr, ctx->log_prefix);

    switch (request_handler(ctx)) {
        case 0:
            respond(ctx);
            request_complete(ctx);
            handle_request(ctx);
            break;
        case 1:
            local_handle(ctx);
            break;
        case 2:
            proxy_handle(ctx);
            break;
        default:
            tcp_close(ctx);
            break;
    }
}

static void init_ctx(client_ctx_t *ctx) {
    ctx->conf = NULL;
    ctx->file = NULL;
    ctx->proxy = NULL;
    ctx->use_fastcgi = 0;
    ctx->chunks_transferred = 0;
    ctx->fcgi_ctx = NULL;
    ctx->use_proxy = 0;
    ctx->ws_close = 0;
    ctx->proxy = NULL;
    ctx->msg_content[0] = 0;
    ctx->msg_buf = NULL;
    ctx->msg_buf_ptr = NULL;
    ctx->req_host[0] = 0;
    ctx->err_msg[0] = 0;
    ctx->req_s = ctx->socket.ts_last;
    ctx->transferred_length = 0;
    ctx->content_length = 0;

    memset(&ctx->uri, 0, sizeof(ctx->uri));
    memset(&ctx->req, 0, sizeof(ctx->req));
    memset(&ctx->res, 0, sizeof(ctx->res));

    ctx->res.status = http_get_status(501);
    http_init_hdr(&ctx->res.hdr);
    sprintf(ctx->res.version, "1.1");

    ctx->status.status = 0;
    ctx->status.origin = NONE;
    ctx->status.ws_key = NULL;
}

static int request_handler(client_ctx_t *ctx) {
    sock *client = &ctx->socket;
    char *err_msg = ctx->err_msg;
    http_res *res = &ctx->res;

    long ret;
    char buf0[1024], buf1[1024];

    ctx->req_s = clock_micros();

    init_ctx(ctx);

    http_add_header_field(&res->hdr, "Date", http_get_date(buf0, sizeof(buf0)));
    http_add_header_field(&res->hdr, "Server", SERVER_STR);
    /*if (ret <= 0) {
        if (errno != 0) return 0;

        ctx->c_keep_alive = 0;
        res->status = http_get_status(408);
        return 0;
    }*/

    http_req *req = &ctx->req;
    ret = http_receive_request(client, req);
    if (ret != 0) {
        ctx->c_keep_alive = 0;
        error("Unable to receive http header");
        sprintf(err_msg, "Unable to receive http header: %s.", error_str(errno, buf0, sizeof(buf0)));
        int err = error_get_http();
        res->status = http_get_status(err == HTTP_ERROR_URI_TOO_LONG ? 414 : (err == HTTP_ERROR_TOO_MANY_HEADER_FIELDS ? 431 : 400));
        errno = 0;
        return 0;
    }

    const char *hdr_connection = http_get_header_field(&req->hdr, "Connection");
    ctx->c_keep_alive = (strcontains(hdr_connection, "keep-alive") || strcontains(hdr_connection, "Keep-Alive"));
    const char *host_ptr = http_get_header_field(&req->hdr, "Host");
    if (host_ptr != NULL && strlen(host_ptr) > 255) {
        ctx->req_host[0] = 0;
        res->status = http_get_status(400);
        sprintf(err_msg, "Host header field is too long.");
        return 0;
    } else if (host_ptr == NULL || strchr(host_ptr, '/') != NULL) {
        if (strchr(ctx->socket.addr, ':') == NULL) {
            strcpy(ctx->req_host, ctx->socket.addr);
        } else {
            sprintf(ctx->req_host, "[%s]", ctx->socket.addr);
        }
        res->status = http_get_status(400);
        sprintf(err_msg, "The client provided no or an invalid Host header field.");
        return 0;
    } else {
        strcpy(ctx->req_host, host_ptr);
    }

    logger_set_prefix("[%s%*s%s]%s", BLD_STR, ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);
    info(BLD_STR "%s %s", req->method, req->uri);

    if (strstarts(req->uri, "/.sesimos/res/")) {
        if (!streq(req->method, "GET") && !streq(req->method, "HEAD")) {
            res->status = http_get_status(405);
            http_add_header_field(&res->hdr, "Allow", "GET, HEAD");
            return 0;
        }

        const res_t resources[] = {
                {"style.css",        "text/css; charset=UTF-8",      http_style_doc,    http_style_doc_size},
                {"icon-error.svg",   "image/svg+xml; charset=UTF-8", http_icon_error,   http_icon_error_size},
                {"icon-info.svg",    "image/svg+xml; charset=UTF-8", http_icon_info,    http_icon_info_size},
                {"icon-success.svg", "image/svg+xml; charset=UTF-8", http_icon_success, http_icon_success_size},
                {"icon-warning.svg", "image/svg+xml; charset=UTF-8", http_icon_warning, http_icon_warning_size},
                {"globe.svg",        "image/svg+xml; charset=UTF-8", http_icon_globe,   http_icon_globe_size},
        };

        res->status = http_get_status(404);
        for (int i = 0; i < sizeof(resources) / sizeof(res_t); i++) {
            const res_t *r = &resources[i];
            if (streq(req->uri + 14, r->name)) {
                res->status = http_get_status(203);
                http_add_header_field(&res->hdr, "Content-Type", r->type);
                http_add_header_field(&res->hdr, "Cache-Control", "public, max-age=86400");
                ctx->msg_buf = (char *) r->content;
                ctx->content_length = r->size;
                break;
            }
        }

        return 0;
    }

    ctx->conf = get_host_config(ctx->req_host);
    if (ctx->conf == NULL) {
        res->status = http_get_status(421);
        strcpy(ctx->err_msg, "The requested host name is not configured on the server.");
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

    if (ctx->conf->type == CONFIG_TYPE_LOCAL && streq(req->method, "TRACE")) {
        return 1;
    } else if (dir_mode != URI_DIR_MODE_NO_VALIDATION) {
        ssize_t size = sizeof(buf0);
        url_decode(req->uri, buf0, &size);
        int change_proto = (!client->enc && !strstarts(uri->uri, "/.well-known/"));
        if (!streq(uri->uri, buf0) || change_proto) {
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

int respond(client_ctx_t *ctx) {
    http_req *req = &ctx->req;
    http_res *res = &ctx->res;
    sock *client = &ctx->socket;
    http_status_ctx *status = &ctx->status;
    char *err_msg = ctx->err_msg;

    long ret = 0;
    char buf0[1024];
    char msg_pre_buf_1[4096], msg_pre_buf_2[4096];
    char buffer[CHUNK_SIZE];

    if (!ctx->use_proxy) {
        if (ctx->conf != NULL && ctx->conf->type == CONFIG_TYPE_LOCAL && ctx->uri.is_static && res->status->code == 405) {
            http_add_header_field(&res->hdr, "Allow", "GET, HEAD, TRACE");
        }
        if (http_get_header_field(&res->hdr, "Accept-Ranges") == NULL) {
            http_add_header_field(&res->hdr, "Accept-Ranges", "none");
        }
        if (!ctx->use_fastcgi && ctx->file == NULL && ctx->msg_buf == NULL && res->status->code != 304) {
            http_remove_header_field(&res->hdr, "Date", HTTP_REMOVE_ALL);
            http_remove_header_field(&res->hdr, "Server", HTTP_REMOVE_ALL);
            http_remove_header_field(&res->hdr, "Cache-Control", HTTP_REMOVE_ALL);
            http_remove_header_field(&res->hdr, "Content-Type", HTTP_REMOVE_ALL);
            http_remove_header_field(&res->hdr, "Content-Encoding", HTTP_REMOVE_ALL);
            http_add_header_field(&res->hdr, "Date", http_get_date(buf0, sizeof(buf0)));
            http_add_header_field(&res->hdr, "Server", SERVER_STR);
            http_add_header_field(&res->hdr, "Cache-Control", "no-cache");
            http_add_header_field(&res->hdr, "Content-Type", "text/html; charset=UTF-8");

            // TODO list Locations on 3xx Redirects
            const http_doc_info *http_info = http_get_status_info(res->status->code);
            const http_status_msg *http_msg = http_get_error_msg(res->status->code);

            if (ctx->msg_content[0] == 0) {
                if (res->status->code >= 300 && res->status->code < 400) {
                    const char *location = http_get_header_field(&res->hdr, "Location");
                    if (location != NULL) {
                        snprintf(ctx->msg_content, sizeof(ctx->msg_content), "      <ul>\n        <li><a href=\"%s\">%s</a></li>\n      </ul>\n", location, location);
                    }
                }
            } else if (strstarts(ctx->msg_content, "<!DOCTYPE html>") || strstarts(ctx->msg_content, "<html")) {
                ctx->msg_content[0] = 0;
                // TODO let relevant information pass?
            }

            char *proxy_doc = "";
            if (ctx->conf != NULL && ctx->conf->type == CONFIG_TYPE_REVERSE_PROXY) {
                const http_status *status_hdr = http_get_status(status->status);
                char stat_str[8];
                sprintf(stat_str, "%03i", status->status);
                snprintf(msg_pre_buf_2, sizeof(msg_pre_buf_2), http_proxy_doc,
                        " success",
                        (status->origin == CLIENT_REQ) ? " error" : " success",
                        (status->origin == INTERNAL) ?   " error" : " success",
                        (status->origin == SERVER_REQ) ? " error" : (status->status == 0 ? "" : " success"),
                        (status->origin == CLIENT_RES) ? " error" : " success",
                        (status->origin == SERVER) ?     " error" : (status->status == 0 ? "" : " success"),
                        (status->origin == SERVER_RES) ? " error" : (status->status == 0 ? "" : " success"),
                        (status->origin == INTERNAL) ?   " error" : " success",
                        (status->origin == INTERNAL || status->origin == SERVER) ? " error" : " success",
                        res->status->code,
                        res->status->msg,
                        (status->status == 0) ? "???" : stat_str,
                        (status_hdr != NULL) ? status_hdr->msg : "",
                        ctx->req_host, SERVER_NAME);
                proxy_doc = msg_pre_buf_2;
            }

            ctx->msg_buf_ptr = malloc(4096);
            ctx->msg_buf = ctx->msg_buf_ptr;
            snprintf(msg_pre_buf_1, sizeof(msg_pre_buf_1), http_info->doc,
                     res->status->code, res->status->msg, http_msg != NULL ? http_msg->msg : "", err_msg);
            ctx->content_length = snprintf(ctx->msg_buf, 4096, http_default_doc, res->status->code, res->status->msg,
                                           msg_pre_buf_1, http_info->mode, http_info->icon, http_info->color,
                                           ctx->req_host, proxy_doc, ctx->msg_content, SERVER_STR_HTML);
        }
        if (ctx->content_length >= 0) {
            sprintf(buf0, "%li", ctx->content_length);
            http_remove_header_field(&res->hdr, "Content-Length", HTTP_REMOVE_ALL);
            http_add_header_field(&res->hdr, "Content-Length", buf0);
        } else if (http_get_header_field(&res->hdr, "Transfer-Encoding") == NULL) {
            ctx->s_keep_alive = 0;
        }
    }

    if (ctx->use_proxy != 2) {
        http_remove_header_field(&res->hdr, "Connection", HTTP_REMOVE_ALL);
        http_remove_header_field(&res->hdr, "Keep-Alive", HTTP_REMOVE_ALL);
        if (ctx->s_keep_alive && ctx->c_keep_alive) {
            http_add_header_field(&res->hdr, "Connection", "keep-alive");
            sprintf(buf0, "timeout=%i, max=%i", CLIENT_TIMEOUT, REQ_PER_CONNECTION);
            http_add_header_field(&res->hdr, "Keep-Alive", buf0);
        } else {
            http_add_header_field(&res->hdr, "Connection", "close");
        }
    }

    http_send_response(client, res);
    ctx->res_ts = clock_micros();
    const char *location = http_get_header_field(&res->hdr, "Location");
    info("%s%s%03i %s%s%s (%s)%s", http_get_status_color(res->status->code), ctx->use_proxy ? "-> " : "", res->status->code,
         res->status->msg, location != NULL ? " -> " : "", location != NULL ? location : "",
         format_duration(ctx->res_ts - ctx->req_s, buf0), CLR_STR);

    // TODO access/error log file

    if (ctx->use_proxy) {
        // reverse proxy
        return 3;
    } else if (!streq(req->method, "HEAD")) {
        // default response
        if (ctx->msg_buf != NULL) {
            ret = sock_send_x(client, ctx->msg_buf, ctx->content_length, 0);
            if (ret <= 0) {
                error("Unable to send");
            }
        } else if (ctx->file != NULL) {
            unsigned long len, snd_len = 0;
            while (snd_len < ctx->content_length) {
                len = fread(buffer, 1, CHUNK_SIZE, ctx->file);
                if (snd_len + len > ctx->content_length) {
                    len = ctx->content_length - snd_len;
                }
                ret = sock_send_x(client, buffer, len, feof(ctx->file) ? 0 : MSG_MORE);
                if (ret <= 0) {
                    error("Unable to send");
                    break;
                }
                snd_len += ret;
            }
        } else if (ctx->use_fastcgi) {
            // FastCGI
            return 2;
        }

        if (ret < 0) ctx->c_keep_alive = 0;
    }

    return 0;
}

void request_complete(client_ctx_t *ctx) {
    char buf[64];
    ctx->req_e = clock_micros();
    info("Transfer complete: %s", format_duration(ctx->req_e - ctx->req_s, buf));

    if (ctx->conf) {
        char path[256];
        sprintf(path, "/var/log/sesimos/%s.access.log", ctx->req_host);
        FILE *log = fopen(path, "a");
        if (log) {
            struct timespec time1, time2;
            clock_gettime(CLOCK_MONOTONIC, &time1);
            clock_gettime(CLOCK_REALTIME, &time2);
            const long diff = (time2.tv_sec - time1.tv_sec) * 1000000 + (time2.tv_nsec - time1.tv_nsec) / 1000;
            struct tm time_info;
            const long ts = (ctx->req_s + diff) / 1000000;
            strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S%z", localtime_r(&ts, &time_info));

            const char *auth = http_get_header_field(&ctx->req.hdr, "Authorization");
            char user[256] = {0};
            if (auth != NULL && strstarts(auth, "Basic ")) {
                base64_decode(auth + 6, strlen(auth) - 6, user, NULL);
                char *col = strchr(user, ':');
                if (col != NULL) col[0] = 0;
            }
            const char *ref = http_get_header_field(&ctx->req.hdr, "Referer");
            const char *ua = http_get_header_field(&ctx->req.hdr, "User-Agent");
            const char *loc = http_get_header_field(&ctx->res.hdr, "Location");
            const char *type = http_get_header_field(&ctx->res.hdr, "Content-Type");
            const long len = ctx->content_length <= 0 ? ctx->transferred_length : ctx->content_length;

            fprintf(log, "%s %s %s [%s] \"%s %s HTTP/%s\" %i %li %s%s%s %s%s%s %s%s%s %s%s%s\n",
                ctx->socket.addr, ctx->host[0] == 0 ? "-" : ctx->host, user[0] != 0 ? user : "-", buf,
                ctx->req.method, ctx->req.uri, ctx->req.version, ctx->res.status->code, len,
                loc != NULL ? "\"" : "", loc != NULL ? loc : "-", loc != NULL ? "\"" : "",
                type != NULL ? "\"" : "", type != NULL ? type : "-", type != NULL ? "\"" : "",
                ref != NULL ? "\"" : "", ref != NULL ? ref : "-", ref != NULL ? "\"" : "",
                ua != NULL ? "\"" : "", ua != NULL ? ua : "-", ua != NULL ? "\"" : "");
            fclose(log);
        }
        errno = 0;
    }

    if (ctx->file) fclose(ctx->file);
    free(ctx->msg_buf_ptr);
    uri_free(&ctx->uri);
    http_free_req(&ctx->req);
    http_free_res(&ctx->res);
}

void timeout_request(client_ctx_t *ctx) {
    init_ctx(ctx);
    logger_set_prefix("[%*s]%s", ADDRSTRLEN, ctx->socket.s_addr, ctx->log_prefix);

    ctx->s_keep_alive = 0;
    ctx->res.status = http_get_status(408);

    respond(ctx);
    request_complete(ctx);
    tcp_close(ctx);
}
