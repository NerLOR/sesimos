/**
 * sesimos - secure, simple, modern web server
 * @brief Client request handler
 * @file src/worker/request_handler.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "../defs.h"
#include "request_handler.h"
#include "../lib/mpmc.h"
#include "tcp_closer.h"
#include "../async.h"

#include "../server.h"
#include "../logger.h"

#include "../lib/utils.h"
#include "../lib/config.h"
#include "../lib/sock.h"
#include "../lib/http.h"
#include "../lib/proxy.h"
#include "../lib/fastcgi.h"
#include "../cache_handler.h"
#include "../lib/compress.h"
#include "../lib/websocket.h"
#include "responder.h"

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <openssl/err.h>
#include <arpa/inet.h>

static mpmc_t mpmc_ctx;

static void request_handler_func(client_ctx_t *ctx);
static int request_handler(client_ctx_t *ctx);

int request_handler_init(int n_workers, int buf_size) {
    return mpmc_init(&mpmc_ctx, n_workers, buf_size, (void (*)(void *)) request_handler_func, "req");
}

int handle_request(client_ctx_t *ctx) {
    return mpmc_queue(&mpmc_ctx, ctx);
}

void request_handler_stop(void) {
    mpmc_stop(&mpmc_ctx);
}

void request_handler_destroy(void) {
    mpmc_destroy(&mpmc_ctx);
}

static void request_handler_func(client_ctx_t *ctx) {
    logger_set_prefix("[%*s]%s", INET6_ADDRSTRLEN, ctx->s_addr, ctx->log_prefix);

    if (request_handler(ctx) == 0) {
        respond(ctx);
    } else {
        tcp_close(ctx);
    }
}

static int request_handler(client_ctx_t *ctx) {
    sock *client = &ctx->socket;
    long ret;

    char buf0[1024], buf1[1024];
    char msg_buf[8192], err_msg[256];
    char msg_content[1024];
    const char *host_ptr, *hdr_connection;

    msg_buf[0] = 0;
    err_msg[0] = 0;
    msg_content[0] = 0;

    int accept_if_modified_since = 0;
    ctx->use_fastcgi = 0;
    ctx->use_proxy = 0;
    int p_len;

    fastcgi_cnx_t fcgi_cnx = {.socket = 0, .req_id = 0, .ctx = ctx};
    http_status custom_status;

    http_res *res = &ctx->res;
    res->status = http_get_status(501);
    res->hdr.field_num = 0;
    res->hdr.last_field_num = -1;
    sprintf(res->version, "1.1");

    http_status_ctx *status = &ctx->status;
    status->status = 0;
    status->origin = NONE;
    status->ws_key = NULL;

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

    hdr_connection = http_get_header_field(&req->hdr, "Connection");
    ctx->c_keep_alive = (hdr_connection != NULL && (strstr(hdr_connection, "keep-alive") != NULL || strstr(hdr_connection, "Keep-Alive") != NULL));
    host_ptr = http_get_header_field(&req->hdr, "Host");
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
                p_len = snprintf(buf1, sizeof(buf1), "https://%s%s", ctx->req_host, buf0);
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
        if (strcmp(req->method, "TRACE") == 0) {
            res->status = http_get_status(200);
            http_add_header_field(&res->hdr, "Content-Type", "message/http");

            ctx->content_length = snprintf(msg_buf, sizeof(msg_buf) - ctx->content_length, "%s %s HTTP/%s\r\n", req->method, req->uri, req->version);
            for (int i = 0; i < req->hdr.field_num; i++) {
                const http_field *f = &req->hdr.fields[i];
                ctx->content_length += snprintf(msg_buf + ctx->content_length, sizeof(msg_buf) - ctx->content_length, "%s: %s\r\n", http_field_get_name(f), http_field_get_value(f));
            }

            return 0;
        }

        if (strncmp(uri->req_path, "/.well-known/", 13) == 0) {
            http_add_header_field(&res->hdr, "Access-Control-Allow-Origin", "*");
        }

        if (strncmp(uri->req_path, "/.well-known/", 13) != 0 && strstr(uri->path, "/.") != NULL) {
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
            http_add_header_field(&res->hdr, "Accept-Ranges", "bytes");
            if (strcmp(req->method, "GET") != 0 && strcmp(req->method, "HEAD") != 0) {
                res->status = http_get_status(405);
                return 0;
            }

            if (http_get_header_field(&req->hdr, "Content-Length") != NULL || http_get_header_field(&req->hdr, "Transfer-Encoding") != NULL) {
                res->status = http_get_status(400);
                sprintf(err_msg, "A GET request must not contain a payload");
                return 0;
            }

            cache_init_uri(ctx->conf->cache, uri);

            const char *last_modified = http_format_date(uri->meta->stat.st_mtime, buf0, sizeof(buf0));
            http_add_header_field(&res->hdr, "Last-Modified", last_modified);
            sprintf(buf1, "%s; charset=%s", uri->meta->type, uri->meta->charset);
            http_add_header_field(&res->hdr, "Content-Type", buf1);


            const char *accept_encoding = http_get_header_field(&req->hdr, "Accept-Encoding");
            int enc = 0;
            if (accept_encoding != NULL) {
                if (uri->meta->filename_comp_br[0] != 0 && strstr(accept_encoding, "br") != NULL) {
                    ctx->file = fopen(uri->meta->filename_comp_br, "rb");
                    if (ctx->file == NULL) {
                        cache_mark_dirty(ctx->conf->cache, uri->filename);
                    } else {
                        http_add_header_field(&res->hdr, "Content-Encoding", "br");
                        enc = COMPRESS_BR;
                    }
                } else if (uri->meta->filename_comp_gz[0] != 0 && strstr(accept_encoding, "gzip") != NULL) {
                    ctx->file = fopen(uri->meta->filename_comp_gz, "rb");
                    if (ctx->file == NULL) {
                        cache_mark_dirty(ctx->conf->cache, uri->filename);
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
                if (enc) {
                    sprintf(buf0, "%s-%s", uri->meta->etag, (enc & COMPRESS_BR) ? "br" : (enc & COMPRESS_GZ) ? "gzip" : "");
                    http_add_header_field(&res->hdr, "ETag", buf0);
                } else {
                    http_add_header_field(&res->hdr, "ETag", uri->meta->etag);
                }
            }

            if (strncmp(uri->meta->type, "text/", 5) == 0) {
                http_add_header_field(&res->hdr, "Cache-Control", "public, max-age=3600");
            } else {
                http_add_header_field(&res->hdr, "Cache-Control", "public, max-age=86400");
            }

            const char *if_modified_since = http_get_header_field(&req->hdr, "If-Modified-Since");
            const char *if_none_match = http_get_header_field(&req->hdr, "If-None-Match");
            if ((if_none_match != NULL && strstr(if_none_match, uri->meta->etag) == NULL) ||
                (accept_if_modified_since && if_modified_since != NULL && strcmp(if_modified_since, last_modified) == 0))
            {
                res->status = http_get_status(304);
                return 0;
            }

            const char *range = http_get_header_field(&req->hdr, "Range");
            if (range != NULL) {
                if (strlen(range) <= 6 || strncmp(range, "bytes=", 6) != 0) {
                    res->status = http_get_status(416);
                    http_remove_header_field(&res->hdr, "Content-Type", HTTP_REMOVE_ALL);
                    http_remove_header_field(&res->hdr, "Last-Modified", HTTP_REMOVE_ALL);
                    http_remove_header_field(&res->hdr, "ETag", HTTP_REMOVE_ALL);
                    http_remove_header_field(&res->hdr, "Cache-Control", HTTP_REMOVE_ALL);
                    return 0;
                }
                range += 6;
                char *ptr = strchr(range, '-');
                if (ptr == NULL) {
                    res->status = http_get_status(416);
                    return 0;
                }
                ctx->file = fopen(uri->filename, "rb");
                fseek(ctx->file, 0, SEEK_END);
                unsigned long file_len = ftell(ctx->file);
                fseek(ctx->file, 0, SEEK_SET);
                if (file_len == 0) {
                    ctx->content_length = 0;
                    return 0;
                }
                long num1 = 0;
                long num2 = (long) file_len - 1;

                if (ptr != range) num1 = (long) strtoul(range, NULL, 10);
                if (ptr[1] != 0) num2 = (long) strtoul(ptr + 1, NULL, 10);

                if (num1 >= file_len || num2 >= file_len || num1 > num2) {
                    res->status = http_get_status(416);
                    return 0;
                }
                sprintf(buf0, "bytes %li-%li/%li", num1, num2, file_len);
                http_add_header_field(&res->hdr, "Content-Range", buf0);

                res->status = http_get_status(206);
                fseek(ctx->file, num1, SEEK_SET);
                ctx->content_length = num2 - num1 + 1;

                return 0;
            }

            if (ctx->file == NULL) {
                ctx->file = fopen(uri->filename, "rb");
            }

            fseek(ctx->file, 0, SEEK_END);
            ctx->content_length = ftell(ctx->file);
            fseek(ctx->file, 0, SEEK_SET);
        } else {
            int mode;
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
            char *last_modified = http_format_date(statbuf.st_mtime, buf0, sizeof(buf0));
            http_add_header_field(&res->hdr, "Last-Modified", last_modified);

            res->status = http_get_status(200);
            if (fastcgi_init(&fcgi_cnx, mode, 0 /* TODO */, ctx->req_num, client, req, uri) != 0) {
                res->status = http_get_status(503);
                sprintf(err_msg, "Unable to communicate with FastCGI socket.");
                return 0;
            }

            const char *client_content_length = http_get_header_field(&req->hdr, "Content-Length");
            const char *client_transfer_encoding = http_get_header_field(&req->hdr, "Transfer-Encoding");
            if (client_content_length != NULL) {
                unsigned long client_content_len = strtoul(client_content_length, NULL, 10);
                ret = fastcgi_receive(&fcgi_cnx, client, client_content_len);
            } else if (client_transfer_encoding != NULL && strstr(client_transfer_encoding, "chunked") != NULL) {
                ret = fastcgi_receive_chunked(&fcgi_cnx, client);
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
                return 0;
            }
            fastcgi_close_stdin(&fcgi_cnx);

            ret = fastcgi_header(&fcgi_cnx, res, err_msg);
            if (ret != 0) {
                return (ret < 0) ? -1 : 0;
            }

            const char *status_hdr = http_get_header_field(&res->hdr, "Status");
            if (status_hdr != NULL) {
                int status_code = (int) strtoul(status_hdr, NULL, 10);
                res->status = http_get_status(status_code);
                http_remove_header_field(&res->hdr, "Status", HTTP_REMOVE_ALL);
                if (res->status == NULL && status_code >= 100 && status_code <= 999) {
                    custom_status.code = status_code;
                    strcpy(custom_status.type, "");
                    strcpy(custom_status.msg, status_hdr + 4);
                    res->status = &custom_status;
                } else if (res->status == NULL) {
                    res->status = http_get_status(500);
                    sprintf(err_msg, "The status_hdr code was set to an invalid or unknown value.");
                    return 0;
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
                ctx->content_length <= sizeof(msg_content) - 1)
            {
                fastcgi_dump(&fcgi_cnx, msg_content, sizeof(msg_content));
                return 0;
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
                    sprintf(buf0, "br");
                } else if (http_comp & COMPRESS_GZ) {
                    ctx->use_fastcgi |= FASTCGI_COMPRESS_GZ;
                    sprintf(buf0, "gzip");
                }
                http_add_header_field(&res->hdr, "Vary", "Accept-Encoding");
                http_add_header_field(&res->hdr, "Content-Encoding", buf0);
                http_remove_header_field(&res->hdr, "Content-Length", HTTP_REMOVE_ALL);
            }

            if (http_get_header_field(&res->hdr, "Content-Length") == NULL) {
                http_add_header_field(&res->hdr, "Transfer-Encoding", "chunked");
            }
        }
    } else if (ctx->conf->type == CONFIG_TYPE_REVERSE_PROXY) {
        info("Reverse proxy for " BLD_STR "%s:%i" CLR_STR, ctx->conf->proxy.hostname, ctx->conf->proxy.port);
        http_remove_header_field(&res->hdr, "Date", HTTP_REMOVE_ALL);
        http_remove_header_field(&res->hdr, "Server", HTTP_REMOVE_ALL);

        ret = proxy_init(req, res, status, ctx->conf, client, ctx, &custom_status, err_msg);
        ctx->use_proxy = (ret == 0);

        if (res->status->code == 101) {
            const char *connection = http_get_header_field(&res->hdr, "Connection");
            const char *upgrade = http_get_header_field(&res->hdr, "Upgrade");
            if (connection != NULL && upgrade != NULL &&
                (strstr(connection, "upgrade") != NULL || strstr(connection, "Upgrade") != NULL) &&
                strcmp(upgrade, "websocket") == 0)
            {
                const char *ws_accept = http_get_header_field(&res->hdr, "Sec-WebSocket-Accept");
                if (ws_calc_accept_key(status->ws_key, buf0) == 0) {
                    ctx->use_proxy = (strcmp(buf0, ws_accept) == 0) ? 2 : 1;
                }
            } else {
                status->status = 101;
                status->origin = INTERNAL;
                res->status = http_get_status(501);
            }
        }

        // Let 300 be formatted by origin server
        if (ctx->use_proxy && res->status->code >= 301 && res->status->code < 600) {
            const char *content_type = http_get_header_field(&res->hdr, "Content-Type");
            const char *content_length_f = http_get_header_field(&res->hdr, "Content-Length");
            const char *content_encoding = http_get_header_field(&res->hdr, "Content-Encoding");
            if (content_encoding == NULL && content_type != NULL && content_length_f != NULL && strncmp(content_type, "text/html", 9) == 0) {
                long content_len = strtol(content_length_f, NULL, 10);
                if (content_len <= sizeof(msg_content) - 1) {
                    if (status->status != 101) {
                        status->status = res->status->code;
                        status->origin = res->status->code >= 400 ? SERVER : NONE;
                    }
                    ctx->use_proxy = 0;
                    proxy_dump(msg_content, content_len);
                }
            }
        }

        /*
        char *content_encoding = http_get_header_field(&res->hdr, "Content-Encoding");
        if (use_proxy && content_encoding == NULL) {
            int http_comp = http_get_compression(&req, &res);
            if (http_comp & COMPRESS_BR) {
                use_proxy |= PROXY_COMPRESS_BR;
            } else if (http_comp & COMPRESS_GZ) {
                use_proxy |= PROXY_COMPRESS_GZ;
            }
        }

        char *transfer_encoding = http_get_header_field(&res->hdr, "Transfer-Encoding");
        int chunked = transfer_encoding != NULL && strcmp(transfer_encoding, "chunked") == 0;
        http_remove_header_field(&res->hdr, "Transfer-Encoding", HTTP_REMOVE_ALL);
        ret = sprintf(buf0, "%s%s%s",
                      (use_proxy & PROXY_COMPRESS_BR) ? "br" :
                      ((use_proxy & PROXY_COMPRESS_GZ) ? "gzip" : ""),
                      ((use_proxy & PROXY_COMPRESS) && chunked) ? ", " : "",
                      chunked ? "chunked" : "");
        if (ret > 0) {
            http_add_header_field(&res->hdr, "Transfer-Encoding", buf0);
        }
        */
    } else {
        error("Unknown host type: %i", ctx->conf->type);
        res->status = http_get_status(501);
    }

    return 0;
}
