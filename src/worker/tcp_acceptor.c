/**
 * sesimos - secure, simple, modern web server
 * @brief TCP acceptor
 * @file src/worker/tcp_acceptor.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "func.h"
#include "../async.h"
#include "../logger.h"
#include "../lib/mpmc.h"
#include "../lib/utils.h"
#include "../lib/geoip.h"
#include "../workers.h"

#include <string.h>
#include <errno.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

static int tcp_acceptor(client_ctx_t *ctx);

void tcp_acceptor_func(client_ctx_t *ctx) {
    if (tcp_acceptor(ctx) == 0) {
        async(ctx->socket.socket, POLLIN, 0, (void (*)(void *)) handle_request, ctx, (void (*)(void *)) tcp_close, ctx);
    } else {
        tcp_close(ctx);
    }
}

static int tcp_acceptor(client_ctx_t *ctx) {
    struct sockaddr_in6 server_addr;

    inet_ntop(ctx->socket.addr.ipv6.sin6_family, &ctx->socket.addr.ipv6.sin6_addr, ctx->_c_addr, sizeof(ctx->_c_addr));
    if (strncmp(ctx->_c_addr, "::ffff:", 7) == 0) {
        ctx->addr = ctx->_c_addr + 7;
    } else {
        ctx->addr = ctx->_c_addr;
    }

    socklen_t len = sizeof(server_addr);
    getsockname(ctx->socket.socket, (struct sockaddr *) &server_addr, &len);
    inet_ntop(server_addr.sin6_family, (void *) &server_addr.sin6_addr, ctx->_s_addr, sizeof(ctx->_s_addr));
    if (strncmp(ctx->_s_addr, "::ffff:", 7) == 0) {
        ctx->s_addr = ctx->_s_addr + 7;
    } else {
        ctx->s_addr = ctx->_s_addr;
    }

    sprintf(ctx->log_prefix, "[%s%4i%s]%s[%*s][%5i]%s", (int) ctx->socket.enc ? HTTPS_STR : HTTP_STR,
            ntohs(server_addr.sin6_port), CLR_STR, /*color_table[0]*/ "", INET6_ADDRSTRLEN, ctx->addr,
            ntohs(ctx->socket.addr.ipv6.sin6_port), CLR_STR);

    logger_set_prefix("[%*s]%s", INET6_ADDRSTRLEN, ctx->s_addr, ctx->log_prefix);
    
    int ret;
    char buf[1024];
    sock *client = &ctx->socket;

    clock_gettime(CLOCK_MONOTONIC, &ctx->begin);

    if (config.dns_server[0] != 0) {
        sprintf(buf, "dig @%s +short +time=1 -x %s", config.dns_server, ctx->addr);
        FILE *dig = popen(buf, "r");
        if (dig == NULL) {
            error("Unable to start dig: %s", strerror(errno));
            goto dig_err;
        }
        unsigned long read = fread(buf, 1, sizeof(buf), dig);
        ret = pclose(dig);
        if (ret != 0) {
            error("Dig terminated with exit code %i", ret);
            goto dig_err;
        }
        char *ptr = memchr(buf, '\n', read);
        if (ptr == buf || ptr == NULL) {
            goto dig_err;
        }
        ptr[-1] = 0;
        strncpy(ctx->host, buf, sizeof(ctx->host));
    } else {
        dig_err:
        ctx->host[0] = 0;
    }

    ctx->cc[0] = 0;
    geoip_lookup_country(&client->addr.sock, ctx->cc);

    info("Connection accepted from %s %s%s%s[%s]", ctx->addr, ctx->host[0] != 0 ? "(" : "",
         ctx->host[0] != 0 ? ctx->host : "", ctx->host[0] != 0 ? ") " : "",
         ctx->cc[0] != 0 ? ctx->cc : "N/A");

    struct timeval client_timeout = {.tv_sec = CLIENT_TIMEOUT, .tv_usec = 0};
    if (setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout)) == -1 ||
        setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout)) == -1)
    {
        error("Unable to set timeout for socket");
        return -1;
    }

    if (client->enc) {
        client->ssl = SSL_new(client->ctx);
        SSL_set_fd(client->ssl, client->socket);
        SSL_set_accept_state(client->ssl);

        ret = SSL_accept(client->ssl);
        client->_last_ret = ret;
        client->_errno = errno;
        client->_ssl_error = ERR_get_error();
        if (ret <= 0) {
            info("Unable to perform handshake: %s", sock_strerror(client));
            return - 1;
        }
    }

    ctx->req_num = 0;
    ctx->s_keep_alive = 1;
    ctx->c_keep_alive = 1;

    return 0;
}
