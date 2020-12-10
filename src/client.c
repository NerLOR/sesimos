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


#define out_1(fmt) fprintf(parent_stdout, "%s" fmt "\n", log_base_prefix)
#define out_2(fmt, args...) fprintf(parent_stdout, "%s" fmt "\n", log_base_prefix, args)

#define out_x(x, arg1, arg2, arg3, arg4, arg5, arg6, arg7, FUNC, ...) FUNC

#define print(...) out_x(, ##__VA_ARGS__, out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), \
                         out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_2(__VA_ARGS__), out_1(__VA_ARGS__))


char *client_addr_str, *client_addr_str_ptr, *server_addr_str, *server_addr_str_ptr, *log_base_prefix, *log_req_prefix;


void client_terminate() {
    // TODO prevent processing of further requests in connection
}

int client_websocket_handler() {
    // TODO implement client_websocket_handler
    return 0;
}

int client_request_handler() {
    // TODO implement client_request_handler
    return 0;
}

int client_connection_handler(int client) {
    char buf1[256];
    char buf2[256];
    print("Connection accepted from %s (%s) [%s]", client_addr_str, client_addr_str, "N/A");

    sprintf(buf1, "Hello World!\nYour address is: %s\n", client_addr_str);
    send(client, buf1, strlen(buf1), 0);
    int len = -1;
    while (len == -1) {
        len = recv(client, &buf1, sizeof(buf1), 0);
    }
    sprintf(buf2, "Thank you, %.*s!\nGood bye!\n", len, buf1);
    send(client, buf2, strlen(buf2), 0);

    close(client);

    print("Connection closed");
    return 0;
}

int client_handler(int client, long client_num, struct sockaddr_in6 *client_addr) {
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
    getsockname(client, (struct sockaddr *) &server_addr_storage, &len);
    server_addr = (struct sockaddr_in6 *) &server_addr_storage;
    server_addr_str_ptr = malloc(INET6_ADDRSTRLEN);
    inet_ntop(server_addr->sin6_family, (void *) &server_addr->sin6_addr, server_addr_str_ptr, INET6_ADDRSTRLEN);
    if (strncmp(server_addr_str_ptr, "::ffff:", 7) == 0) {
        server_addr_str = server_addr_str_ptr + 7;
    } else {
        server_addr_str = server_addr_str_ptr;
    }

    log_base_prefix = malloc(256);
    sprintf(log_base_prefix, "[%24s][%s%4i%s]%s[%*s][%5i]%s ",
            server_addr_str, R_STR, ntohs(server_addr->sin6_port), CLR_STR,
            color_table[client_num % 6], INET_ADDRSTRLEN, client_addr_str, ntohs(client_addr->sin6_port), CLR_STR);

    int ret = client_connection_handler(client);
    free(client_addr_str_ptr);
    free(server_addr_str_ptr);
    free(log_base_prefix);
    return ret;
}
