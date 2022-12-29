/**
 * sesimos - secure, simple, modern web server
 * @brief HTTP responder
 * @file src/worker/responder.c
 * @author Lorenz Stechauner
 * @date 2022-12-29
 */

#include "../defs.h"
#include "func.h"
#include "../async.h"
#include "../logger.h"

#include "../lib/utils.h"
#include "../lib/proxy.h"
#include "../lib/fastcgi.h"
#include "../lib/websocket.h"
#include "../workers.h"

#include <string.h>
#include <unistd.h>
#include <openssl/err.h>
#include <arpa/inet.h>

static int responder(client_ctx_t *ctx);

void responder_func(client_ctx_t *ctx) {
    logger_set_prefix("[%s%*s%s]%s", BLD_STR, INET6_ADDRSTRLEN, ctx->req_host, CLR_STR, ctx->log_prefix);
    responder(ctx);

    if (ctx->c_keep_alive && ctx->s_keep_alive && ctx->req_num < REQ_PER_CONNECTION) {
        async(ctx->socket.socket, POLLIN, 0, (void (*)(void *)) handle_request, ctx, (void (*)(void *)) tcp_close, ctx);
    } else {
        tcp_close(ctx);
    }
}

static int responder(client_ctx_t *ctx) {
    sock *client = &ctx->socket;
    long ret = 0;

    char buf0[1024];
    char msg_buf[8192], msg_pre_buf_1[4096], msg_pre_buf_2[4096], err_msg[256];
    char msg_content[1024];
    char buffer[CHUNK_SIZE];

    msg_buf[0] = 0;
    err_msg[0] = 0;
    msg_content[0] = 0;

    fastcgi_cnx_t fcgi_cnx = {.socket = 0, .req_id = 0, .ctx = ctx};

    http_req *req = &ctx->req;
    http_res *res = &ctx->res;
    http_status_ctx status = {.status = 0, .origin = NONE, .ws_key = NULL};

    if (!ctx->use_proxy) {
        if (ctx->conf != NULL && ctx->conf->type == CONFIG_TYPE_LOCAL && ctx->uri.is_static && res->status->code == 405) {
            http_add_header_field(&res->hdr, "Allow", "GET, HEAD, TRACE");
        }
        if (http_get_header_field(&res->hdr, "Accept-Ranges") == NULL) {
            http_add_header_field(&res->hdr, "Accept-Ranges", "none");
        }
        if (!ctx->use_fastcgi && ctx->file == NULL) {
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
            const http_doc_info *info = http_get_status_info(res->status);
            const http_status_msg *http_msg = http_get_error_msg(res->status);

            if (msg_content[0] == 0) {
                if (res->status->code >= 300 && res->status->code < 400) {
                    const char *location = http_get_header_field(&res->hdr, "Location");
                    if (location != NULL) {
                        snprintf(msg_content, sizeof(msg_content), "<ul>\n\t<li><a href=\"%s\">%s</a></li>\n</ul>\n", location, location);
                    }
                }
            } else if (strncmp(msg_content, "<!DOCTYPE html>", 15) == 0 || strncmp(msg_content, "<html", 5) == 0) {
                msg_content[0] = 0;
                // TODO let relevant information pass?
            }

            char *proxy_doc = "";
            if (ctx->conf != NULL && ctx->conf->type == CONFIG_TYPE_REVERSE_PROXY) {
                const http_status *status_hdr = http_get_status(status.status);
                char stat_str[8];
                sprintf(stat_str, "%03i", status.status);
                sprintf(msg_pre_buf_2, http_proxy_document,
                        " success",
                        (status.origin == CLIENT_REQ) ? " error" : " success",
                        (status.origin == INTERNAL) ? " error" : " success",
                        (status.origin == SERVER_REQ) ? " error" : (status.status == 0 ? "" : " success"),
                        (status.origin == CLIENT_RES) ? " error" : " success",
                        (status.origin == SERVER) ? " error" : (status.status == 0 ? "" : " success"),
                        (status.origin == SERVER_RES) ? " error" : (status.status == 0 ? "" : " success"),
                        (status.origin == INTERNAL) ? " error" : " success",
                        (status.origin == INTERNAL || status.origin == SERVER) ? " error" : " success",
                        res->status->code,
                        res->status->msg,
                        (status.status == 0) ? "???" : stat_str,
                        (status_hdr != NULL) ? status_hdr->msg : "",
                        ctx->req_host);
                proxy_doc = msg_pre_buf_2;
            }

            sprintf(msg_pre_buf_1, info->doc, res->status->code, res->status->msg, http_msg != NULL ? http_msg->msg : "", err_msg[0] != 0 ? err_msg : "");
            ctx->content_length = snprintf(msg_buf, sizeof(msg_buf), http_default_document, res->status->code,
                                      res->status->msg, msg_pre_buf_1, info->mode, info->icon, info->color, ctx->req_host,
                                      proxy_doc, msg_content[0] != 0 ? msg_content : "");
        }
        if (ctx->content_length >= 0) {
            sprintf(buf0, "%li", ctx->content_length);
            http_remove_header_field(&res->hdr, "Content-Length", HTTP_REMOVE_ALL);
            http_add_header_field(&res->hdr, "Content-Length", buf0);
        } else if (http_get_header_field(&res->hdr, "Transfer-Encoding") == NULL) {
            ctx->s_keep_alive = 0;
        }
    }

    int close_proxy = 0;
    if (ctx->use_proxy != 2) {
        const char *conn = http_get_header_field(&res->hdr, "Connection");
        close_proxy = (conn == NULL || (strstr(conn, "keep-alive") == NULL && strstr(conn, "Keep-Alive") == NULL));
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
    clock_gettime(CLOCK_MONOTONIC, &ctx->end);
    const char *location = http_get_header_field(&res->hdr, "Location");
    unsigned long micros = (ctx->end.tv_nsec - ctx->begin.tv_nsec) / 1000 + (ctx->end.tv_sec - ctx->begin.tv_sec) * 1000000;
    info("%s%s%03i %s%s%s (%s)%s", http_get_status_color(res->status), ctx->use_proxy ? "-> " : "", res->status->code,
         res->status->msg, location != NULL ? " -> " : "", location != NULL ? location : "",
         format_duration(micros, buf0), CLR_STR);

    // TODO access/error log file

    if (ctx->use_proxy == 2) {
        // WebSocket
        info("Upgrading connection to WebSocket connection");
        ret = ws_handle_connection(client, &proxy);
        if (ret != 0) {
            ctx->c_keep_alive = 0;
            close_proxy = 1;
        }
        info("WebSocket connection closed");
    } else if (strcmp(req->method, "HEAD") != 0) {
        // default response
        unsigned long snd_len = 0;
        unsigned long len;
        if (msg_buf[0] != 0) {
            ret = sock_send(client, msg_buf, ctx->content_length, 0);
            if (ret <= 0) {
                error("Unable to send: %s", sock_strerror(client));
            }
            snd_len += ret;
        } else if (ctx->file != NULL) {
            while (snd_len < ctx->content_length) {
                len = fread(buffer, 1, CHUNK_SIZE, ctx->file);
                if (snd_len + len > ctx->content_length) {
                    len = ctx->content_length - snd_len;
                }
                ret = sock_send(client, buffer, len, feof(ctx->file) ? 0 : MSG_MORE);
                if (ret <= 0) {
                    error("Unable to send: %s", sock_strerror(client));
                    break;
                }
                snd_len += ret;
            }
        } else if (ctx->use_fastcgi) {
            const char *transfer_encoding = http_get_header_field(&res->hdr, "Transfer-Encoding");
            int chunked = (transfer_encoding != NULL && strstr(transfer_encoding, "chunked") != NULL);

            int flags = (chunked ? FASTCGI_CHUNKED : 0) | (ctx->use_fastcgi & (FASTCGI_COMPRESS | FASTCGI_COMPRESS_HOLD));
            ret = fastcgi_send(&fcgi_cnx, client, flags);
        } else if (ctx->use_proxy) {
            const char *transfer_encoding = http_get_header_field(&res->hdr, "Transfer-Encoding");
            int chunked = transfer_encoding != NULL && strstr(transfer_encoding, "chunked") != NULL;

            const char *content_len = http_get_header_field(&res->hdr, "Content-Length");
            unsigned long len_to_send = 0;
            if (content_len != NULL) {
                len_to_send = strtol(content_len, NULL, 10);
            }

            int flags = (chunked ? PROXY_CHUNKED : 0) | (ctx->use_proxy & PROXY_COMPRESS);
            ret = proxy_send(client, len_to_send, flags);
        }

        if (ret < 0) {
            ctx->c_keep_alive = 0;
        }
    }

    if (close_proxy && proxy.socket != 0) {
        info(BLUE_STR "Closing proxy connection");
        sock_close(&proxy);
    }

    clock_gettime(CLOCK_MONOTONIC, &ctx->end);
    micros = (ctx->end.tv_nsec - ctx->begin.tv_nsec) / 1000 + (ctx->end.tv_sec - ctx->begin.tv_sec) * 1000000;
    info("Transfer complete: %s", format_duration(micros, buf0));

    uri_free(&ctx->uri);
    if (fcgi_cnx.socket != 0) {
        close(fcgi_cnx.socket);
        fcgi_cnx.socket = 0;
    }
    http_free_req(req);
    http_free_res(res);

    return 0;
}
