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
#include "../lib/proxy.h"
#include "../lib/websocket.h"

#include <string.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <unistd.h>

static int request_handler(client_ctx_t *ctx);

void request_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%*s]%s", INET6_ADDRSTRLEN, ctx->s_addr, ctx->log_prefix);

    switch (request_handler(ctx)) {
        case 0:
            respond(ctx);
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

int respond(client_ctx_t *ctx) {
    http_req *req = &ctx->req;
    http_res *res = &ctx->res;
    sock *client = &ctx->socket;
    http_status_ctx *status = &ctx->status;
    fastcgi_cnx_t *fcgi_cnx = &ctx->fcgi_cnx;
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

            if (ctx->msg_content[0] == 0) {
                if (res->status->code >= 300 && res->status->code < 400) {
                    const char *location = http_get_header_field(&res->hdr, "Location");
                    if (location != NULL) {
                        snprintf(ctx->msg_content, sizeof(ctx->msg_content), "<ul>\n\t<li><a href=\"%s\">%s</a></li>\n</ul>\n", location, location);
                    }
                }
            } else if (strncmp(ctx->msg_content, "<!DOCTYPE html>", 15) == 0 || strncmp(ctx->msg_content, "<html", 5) == 0) {
                ctx->msg_content[0] = 0;
                // TODO let relevant information pass?
            }

            char *proxy_doc = "";
            if (ctx->conf != NULL && ctx->conf->type == CONFIG_TYPE_REVERSE_PROXY) {
                const http_status *status_hdr = http_get_status(status->status);
                char stat_str[8];
                sprintf(stat_str, "%03i", status->status);
                sprintf(msg_pre_buf_2, http_proxy_document,
                        " success",
                        (status->origin == CLIENT_REQ) ? " error" : " success",
                        (status->origin == INTERNAL) ? " error" : " success",
                        (status->origin == SERVER_REQ) ? " error" : (status->status == 0 ? "" : " success"),
                        (status->origin == CLIENT_RES) ? " error" : " success",
                        (status->origin == SERVER) ? " error" : (status->status == 0 ? "" : " success"),
                        (status->origin == SERVER_RES) ? " error" : (status->status == 0 ? "" : " success"),
                        (status->origin == INTERNAL) ? " error" : " success",
                        (status->origin == INTERNAL || status->origin == SERVER) ? " error" : " success",
                        res->status->code,
                        res->status->msg,
                        (status->status == 0) ? "???" : stat_str,
                        (status_hdr != NULL) ? status_hdr->msg : "",
                        ctx->req_host);
                proxy_doc = msg_pre_buf_2;
            }

            sprintf(msg_pre_buf_1, info->doc, res->status->code, res->status->msg, http_msg != NULL ? http_msg->msg : "", err_msg[0] != 0 ? err_msg : "");
            ctx->content_length = snprintf(ctx->msg_buf, sizeof(ctx->msg_buf), http_default_document, res->status->code,
                                           res->status->msg, msg_pre_buf_1, info->mode, info->icon, info->color, ctx->req_host,
                                           proxy_doc, ctx->msg_content[0] != 0 ? ctx->msg_content : "");
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
        if (ctx->msg_buf[0] != 0) {
            ret = sock_send(client, ctx->msg_buf, ctx->content_length, 0);
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
            ret = fastcgi_send(fcgi_cnx, client, flags);
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
    if (fcgi_cnx->socket != 0) {
        close(fcgi_cnx->socket);
        fcgi_cnx->socket = 0;
    }
    http_free_req(req);
    http_free_res(res);

    return 0;
}
