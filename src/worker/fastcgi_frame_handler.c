/**
 * sesimos - secure, simple, modern web server
 * @brief FastCGI frame handler
 * @file src/worker/fcti_frame_handler.c
 * @author Lorenz Stechauner
 * @date 2023-01-22
 */

#include "func.h"
#include "../lib/fastcgi.h"
#include "../logger.h"
#include "../workers.h"

#include <errno.h>
#include <memory.h>
#include <unistd.h>

void fastcgi_frame_handler_func(fastcgi_ctx_t *ctx) {
    logger_set_prefix("[%*s]%s", ADDRSTRLEN, ctx->client->socket.s_addr, ctx->client->log_prefix);

    switch (fastcgi_recv_frame(&ctx->cnx)) {
        case FCGI_STDOUT:
        case FCGI_STDERR:
            fastcgi_handle_frame(ctx);
            break;
        case -1:
            error("Unable to receive FastCGI frame");
            ctx->client->s_keep_alive = 0;
            fastcgi_close(ctx);
            break;
        default:
            // end of request received
            write(ctx->cnx.fd_out, "\0\0\0\0\0\0\0\0\r\n", 10);
            fastcgi_close(ctx);
    }
}

int fastcgi_handle_connection(client_ctx_t *ctx, fastcgi_cnx_t **cnx) {
    sock_set_timeout(&(*cnx)->socket, FASTCGI_TIMEOUT);
    sock_set_socket_timeout(&(*cnx)->socket, 1);

    fastcgi_ctx_t *a = malloc(sizeof(fastcgi_ctx_t));
    a->closed = 0;
    a->client = ctx;
    memcpy(&a->cnx, *cnx, sizeof(fastcgi_cnx_t));
    ctx->fcgi_ctx = a;
    fastcgi_handle_frame(a);
    *cnx = &a->cnx;

    return 0;
}

void fastcgi_close(fastcgi_ctx_t *ctx) {
    if (ctx->closed == 0) {
        ctx->closed++;
        return;
    }

    logger_set_prefix("[%*s]%s", ADDRSTRLEN, ctx->client->socket.s_addr, ctx->client->log_prefix);

    fastcgi_php_error(&ctx->cnx, NULL);

    if (ctx->cnx.app_status != 0)
        error("FastCGI app terminated with exit code %i", ctx->cnx.app_status);

    debug("Closing FastCGI connection");

    fastcgi_close_cnx(&ctx->cnx);
    ctx->client->fcgi_ctx = NULL;
    free(ctx);
    errno = 0;
}
