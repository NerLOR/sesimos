/**
 * sesimos - secure, simple, modern web server
 * @brief WebSocket frame handler
 * @file src/worker/ws_frame_handler.c
 * @author Lorenz Stechauner
 * @date 2022-12-30
 */

#include "../defs.h"
#include "func.h"
#include "../logger.h"
#include "../lib/websocket.h"
#include "../workers.h"

#include <errno.h>

static int ws_frame_handler(ws_ctx_t *ctx);

void ws_frame_handler_func(ws_ctx_t *ctx) {
    logger_set_prefix("[%*s]%s", ADDRSTRLEN, ctx->client->socket.s_addr, ctx->client->log_prefix);

    if (ws_frame_handler(ctx) == 0) {
        if (ctx->client->ws_close == 3) {
            ws_close(ctx);
        } else {
            ws_handle_frame(ctx);
        }
    } else {
        ws_close(ctx);
    }
}

int ws_handle_connection(client_ctx_t *ctx) {
    info("Upgrading to WebSocket connection");
    sock_set_timeout(&ctx->socket, WS_TIMEOUT);
    sock_set_timeout(&ctx->proxy->proxy, WS_TIMEOUT);

    ws_ctx_t *a = malloc(sizeof(ws_ctx_t));
    ws_ctx_t *b = malloc(sizeof(ws_ctx_t));

    a->other = b,             b->other = a;
    a->client = ctx,          b->client = ctx;
    a->socket = &ctx->socket, b->socket = &ctx->proxy->proxy;

    ws_handle_frame(a);
    ws_handle_frame(b);

    return 0;
}

static int ws_frame_handler(ws_ctx_t *ctx) {
    ws_frame frame;
    char buf[CHUNK_SIZE];

    sock *socket = ctx->socket;
    sock *other = (ctx->socket == &ctx->client->socket) ? &ctx->client->proxy->proxy : &ctx->client->socket;

    if (ws_recv_frame_header(socket, &frame) != 0)
        return -1;

    debug("WebSocket: Peer %s, Opcode=0x%X, Len=%li", (ctx->socket == &ctx->client->socket) ? "client" : "server", frame.opcode, frame.len);

    if (frame.opcode == 0x8) {
        ctx->client->ws_close |= (ctx->socket == &ctx->client->socket) ? 1 : 2;
    }

    if (ws_send_frame_header(other, &frame) != 0)
        return -1;

    if (frame.len > 0) {
        long ret = sock_splice(other, socket, buf, sizeof(buf), frame.len);
        if (ret < 0) {
            error("Unable to forward data in WebSocket");
            return -1;
        } else if (ret != frame.len) {
            error("Unable to forward correct number of bytes in WebSocket");
            return -1;
        }
    }

    return 0;
}

void ws_close(ws_ctx_t *ctx) {
    ws_ctx_t *other = ctx->other;
    if (other) {
        other->other = NULL;
        logger_set_prefix("[%*s]%s", ADDRSTRLEN, ctx->client->socket.s_addr, ctx->client->log_prefix);
        info("Closing WebSocket connection");
        proxy_close(ctx->client->proxy);
        tcp_close(ctx->client);
    }
    free(ctx);
    errno = 0;
}
