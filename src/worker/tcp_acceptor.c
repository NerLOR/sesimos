/**
 * sesimos - secure, simple, modern web server
 * @brief TCP acceptor
 * @file src/worker/tcp_acceptor.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "func.h"
#include "../logger.h"
#include "../lib/utils.h"
#include "../lib/geoip.h"
#include "../workers.h"
#include "../server.h"
#include "../lib/error.h"

#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>

static int tcp_acceptor(client_ctx_t *ctx);

void tcp_acceptor_func(client_ctx_t *ctx) {
    if (tcp_acceptor(ctx) == 0) {
        handle_request(ctx);
    } else {
        tcp_close(ctx);
    }
}

static int tcp_acceptor(client_ctx_t *ctx) {
    struct sockaddr_in6 server_addr;

    memset(ctx->_c_addr, 0, sizeof(ctx->_c_addr));
    memset(ctx->_s_addr, 0, sizeof(ctx->_s_addr));
    inet_ntop(ctx->socket._addr.ipv6.sin6_family, &ctx->socket._addr.ipv6.sin6_addr, ctx->_c_addr, sizeof(ctx->_c_addr));
    if (strstarts(ctx->_c_addr, "::ffff:")) {
        ctx->socket.addr = ctx->_c_addr + 7;
    } else {
        ctx->socket.addr = ctx->_c_addr;
    }

    socklen_t len = sizeof(server_addr);
    getsockname(ctx->socket.socket, (struct sockaddr *) &server_addr, &len);
    inet_ntop(server_addr.sin6_family, (void *) &server_addr.sin6_addr, ctx->_s_addr, sizeof(ctx->_s_addr));
    if (strstarts(ctx->_s_addr, "::ffff:")) {
        ctx->socket.s_addr = ctx->_s_addr + 7;
    } else {
        ctx->socket.s_addr = ctx->_s_addr;
    }

    sprintf(ctx->log_prefix, "[%s%4i%s]%s[%*s][%5i]%s", (int) ctx->socket.enc ? HTTPS_STR : HTTP_STR,
            ntohs(server_addr.sin6_port), CLR_STR, /*color_table[0]*/ "", ADDRSTRLEN, ctx->socket.addr,
            ntohs(ctx->socket._addr.ipv6.sin6_port), CLR_STR);

    logger_set_prefix("[%*s]%s", ADDRSTRLEN, ctx->socket.s_addr, ctx->log_prefix);

    sock *client = &ctx->socket;
    ctx->cnx_s = clock_micros();

    sock_reverse_lookup(&ctx->socket, ctx->host, sizeof(ctx->host));

    ctx->cc[0] = 0;
    geoip_lookup_country(&client->_addr.sock, ctx->cc);

    info("Connection accepted from %s %s%s%s[%s]", ctx->socket.addr, ctx->host[0] != 0 ? "(" : "",
         ctx->host[0] != 0 ? ctx->host : "", ctx->host[0] != 0 ? ") " : "",
         ctx->cc[0] != 0 ? ctx->cc : "N/A");

    if (sock_set_socket_timeout(client, 1) != 0 || sock_set_timeout(client, CLIENT_TIMEOUT) != 0) {
        error("Unable to set timeout for socket");
        return -1;
    }

    if (client->enc) {
        client->ssl = SSL_new(client->ctx);
        SSL_set_fd(client->ssl, client->socket);
        SSL_set_accept_state(client->ssl);

        int ret;
        if ((ret = SSL_accept(client->ssl)) != 1) {
            sock_error(client, ret);
            info("Unable to perform handshake");
            return -1;
        }
        client->ts_last = clock_micros();
        client->ts_last_send = client->ts_last;
    }

    ctx->req_num = 0;
    ctx->s_keep_alive = 1;
    ctx->c_keep_alive = 1;
    ctx->chunks_transferred = 0;

    return 0;
}

void tcp_close(client_ctx_t *ctx) {
    errno = 0;
    logger_set_prefix("[%*s]%s", ADDRSTRLEN, ctx->socket.s_addr, ctx->log_prefix);

    sock_close(&ctx->socket);

    ctx->cnx_e = clock_micros();
    char buf[32];
    info("Connection closed (%s)", format_duration(ctx->cnx_e - ctx->cnx_s, buf));

    server_free_client(ctx);
}
