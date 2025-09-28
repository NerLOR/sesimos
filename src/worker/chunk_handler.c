/**
 * sesimos - secure, simple, modern web server
 * @brief FastCGI frame handler
 * @file src/worker/fcgi_frame_handler.c
 * @author Lorenz Stechauner
 * @date 2023-01-22
 */

#include "func.h"
#include "../logger.h"
#include "../workers.h"

#include <errno.h>

void chunk_handler_func(chunk_ctx_t *ctx) {
    logger_set_prefix("[%*s]%s", ADDRSTRLEN, ctx->client->socket.s_addr, ctx->client->log_prefix);

    char buf[CHUNK_SIZE];
    const long sent = sock_splice_chunked(&ctx->client->socket, ctx->socket, buf, sizeof(buf), ctx->flags | SOCK_SINGLE_CHUNK);
    if (sent < 0) {
        // error
        error("Unable to splice chunk");
        errno = 0;
        ctx->err_cb(ctx);
    } else if (sent == 0) {
        // last chunk
        ctx->client->chunks_transferred = 1;
        ctx->next_cb(ctx);
    } else {
        // next chunk
        ctx->client->transferred_length += sent;
        handle_chunk(ctx);
        return;
    }

    free(ctx);
}

int handle_chunks(client_ctx_t *ctx, sock *socket, int flags, void (*next_cb)(chunk_ctx_t *), void (*err_cb)(chunk_ctx_t *)) {
    chunk_ctx_t *a = malloc(sizeof(chunk_ctx_t));

    a->client = ctx;
    a->socket = socket;
    a->flags = flags;
    a->next_cb = (void (*)(void *)) next_cb;
    a->err_cb  = (void (*)(void *)) err_cb;

    handle_chunk(a);

    return 0;
}
