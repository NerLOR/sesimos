/**
 * Necronda Web Server
 * Client connection and request handlers
 * src/client.c
 * Lorenz Stechauner, 2020-12-03
 */

#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

#include "necronda-server.h"
#include "utils.h"
#include "net/http.h"


#define out_1(fmt) fprintf(parent_stdout, "%s" fmt "\n", log_prefix)
#define out_2(fmt, args...) fprintf(parent_stdout, "%s" fmt "\n", log_prefix, args)

#define out_x(x, arg1, arg2, arg3, arg4, arg5, arg6, arg7, FUNC, ...) FUNC

#define print(...) out_x(, ##__VA_ARGS__, out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), \
                         out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_1(__VA_ARGS__))


int keep_alive = 1;
char *client_addr_str, *client_addr_str_ptr, *server_addr_str, *server_addr_str_ptr,
        *log_prefix, *log_conn_prefix, *log_req_prefix;


char *format_duration(unsigned long micros, char *buf) {
    if (micros < 10000) {
        sprintf(buf, "%.1f ms", (double) micros / 1000.0);
    } else if (micros < 1000000) {
        sprintf(buf, "%li ms", micros / 1000);
    } else if (micros < 100000000) {
        sprintf(buf, "%.2f s", (double) micros / 1000000.0);
    } else if (micros < 1000000000) {
        sprintf(buf, "%.1f s", (double) micros / 1000000.0);
    } else {
        sprintf(buf, "%li s", micros / 1000000);
    }
    return buf;
}

void client_terminate() {
    keep_alive = 0;
    // TODO prevent processing of further requests in connection
}

int client_websocket_handler() {
    // TODO implement client_websocket_handler
    return 0;
}

int client_request_handler(sock *client, int req_num) {
    // TODO implement client_request_handler
    return 0;
}

int client_connection_handler(sock *client) {
    int ret, req_num;
    char buf[16];
    struct timespec begin, end;

    clock_gettime(CLOCK_MONOTONIC, &begin);
    print("Connection accepted from %s (%s) [%s]", client_addr_str, client_addr_str, "N/A");

    struct timeval timeout = {.tv_sec = 3600, .tv_usec = 0};
    if (setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) goto set_timeout_err;
    if (setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        set_timeout_err:
        print(ERR_STR "Unable to set timeout for socket: %s" CLR_STR, strerror(errno));
        return 1;
    }

    if (client->enc) {
        client->ssl = SSL_new(client->ctx);
        SSL_set_fd(client->ssl, client->socket);
        SSL_set_accept_state(client->ssl);

        ret = SSL_accept(client->ssl);
        if (ret <= 0) {
            print(ERR_STR "Unable to perform handshake: %s" CLR_STR, ssl_get_error(client->ssl, ret));
            goto close;
        }
    }

    req_num = 0;
    ret = 0;
    while (ret == 0 && keep_alive && req_num < REQ_PER_CONNECTION) {
        ret = client_request_handler(client, req_num++);
        log_prefix = log_conn_prefix;
    }

    close:
    if (client->enc) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    shutdown(client->socket, SHUT_RDWR);
    close(client->socket);
    clock_gettime(CLOCK_MONOTONIC, &end);

    unsigned long micros = (end.tv_nsec - begin.tv_nsec) / 1000 + (end.tv_sec - begin.tv_sec) * 1000000;

    print("Connection closed (%s)", format_duration(micros, buf));
    return 0;
}

int client_handler(sock *client, long client_num, struct sockaddr_in6 *client_addr) {
    int ret;
    struct sockaddr_in6 *server_addr;
    struct sockaddr_storage server_addr_storage;

    char *color_table[] = {"\x1B[31m", "\x1B[32m", "\x1B[33m", "\x1B[34m", "\x1B[35m", "\x1B[36m"};

    signal(SIGINT, client_terminate);
    signal(SIGTERM, client_terminate);

    client_addr_str_ptr = malloc(INET6_ADDRSTRLEN);
    inet_ntop(client_addr->sin6_family, (void *) &client_addr->sin6_addr, client_addr_str_ptr, INET6_ADDRSTRLEN);
    if (strncmp(client_addr_str_ptr, "::ffff:", 7) == 0) {
        client_addr_str = client_addr_str_ptr + 7;
    } else {
        client_addr_str = client_addr_str_ptr;
    }

    socklen_t len = sizeof(server_addr_storage);
    getsockname(client->socket, (struct sockaddr *) &server_addr_storage, &len);
    server_addr = (struct sockaddr_in6 *) &server_addr_storage;
    server_addr_str_ptr = malloc(INET6_ADDRSTRLEN);
    inet_ntop(server_addr->sin6_family, (void *) &server_addr->sin6_addr, server_addr_str_ptr, INET6_ADDRSTRLEN);
    if (strncmp(server_addr_str_ptr, "::ffff:", 7) == 0) {
        server_addr_str = server_addr_str_ptr + 7;
    } else {
        server_addr_str = server_addr_str_ptr;
    }

    log_conn_prefix = malloc(256);
    sprintf(log_conn_prefix, "[%24s][%s%4i%s]%s[%*s][%5i]%s ",
            server_addr_str, client->enc ? HTTPS_STR : HTTP_STR, ntohs(server_addr->sin6_port), CLR_STR,
            color_table[client_num % 6], INET_ADDRSTRLEN, client_addr_str, ntohs(client_addr->sin6_port), CLR_STR);
    log_prefix = log_conn_prefix;

    ret = client_connection_handler(client);
    free(client_addr_str_ptr);
    free(server_addr_str_ptr);
    free(log_conn_prefix);
    free(log_req_prefix);
    return ret;
}
