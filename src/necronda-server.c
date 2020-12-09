/**
 * Necronda Web Server
 * Main executable
 * src/necronda-server.c
 * Lorenz Stechauner, 2020-12-03
 */

#include "necronda-server.h"

#include <stdio.h>
#include <sys/socket.h>
#include <signal.h>
#include <sys/select.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>

#include "utils.c"
#include "net/http.c"
#include "client.c"


int main(int argc, const char *argv[]) {
    const int YES = 1;
    fd_set socket_fds, read_socket_fds;
    int max_socket_fd = 0;
    int ready_sockets_num = 0;

    const struct sockaddr_in addresses[2] = {
            {.sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(8080)},
            {.sin_family = AF_INET, .sin_addr.s_addr = INADDR_ANY, .sin_port = htons(4443)}
    };
    const struct sockaddr_in6 addresses6[2] = {
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(8080)},
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(4443)}
    };

    printf("Necronda Web Server\n");

    SOCKETS[0] = socket(AF_INET, SOCK_STREAM, 0);
    if (SOCKETS[0] == -1) goto socket_err;
    SOCKETS[1] = socket(AF_INET, SOCK_STREAM, 0);
    if (SOCKETS[1] == -1) goto socket_err;
    SOCKETS[2] = socket(AF_INET6, SOCK_STREAM, 0);
    if (SOCKETS[2] == -1) goto socket_err;
    SOCKETS[3] = socket(AF_INET6, SOCK_STREAM, 0);
    if (SOCKETS[3] == -1) {
        socket_err:
        fprintf(stderr, ERR_STR "Unable to create socket: %s" CLR_STR "\n", strerror(errno));
        return 1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (setsockopt(SOCKETS[i], SOL_SOCKET, SO_REUSEADDR, &YES, sizeof(YES)) == -1) {
            fprintf(stderr, ERR_STR "Unable to set options for socket %i: %s" CLR_STR "\n", i, strerror(errno));
            return 1;
        }
    }

    if (bind(SOCKETS[0], (struct sockaddr *) &addresses[0], sizeof(addresses[0])) == -1) goto bind_err;
    if (bind(SOCKETS[1], (struct sockaddr *) &addresses[1], sizeof(addresses[1])) == -1) goto bind_err;
    if (bind(SOCKETS[2], (struct sockaddr *) &addresses6[0], sizeof(addresses6[0])) == -1) goto bind_err;
    if (bind(SOCKETS[3], (struct sockaddr *) &addresses6[1], sizeof(addresses6[1])) == -1) {
        bind_err:
        fprintf(stderr, ERR_STR "Unable to bind socket to address: %s" CLR_STR "\n", strerror(errno));
        return 1;
    }

    // TODO implement TLS server side handshake

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (listen(SOCKETS[i], LISTEN_BACKLOG) == -1) {
            fprintf(stderr, ERR_STR "Unable to listen on socket %i: %s" CLR_STR "\n", i, strerror(errno));
            return 1;
        }
    }

    FD_ZERO(&socket_fds);
    for (int i = 0; i < NUM_SOCKETS; i++) {
        FD_SET(SOCKETS[i], &socket_fds);
        if (SOCKETS[i] > max_socket_fd) {
            max_socket_fd = SOCKETS[i];
        }
    }

    while (1) {
        read_socket_fds = socket_fds;
        ready_sockets_num = select(max_socket_fd, &read_socket_fds, NULL, NULL, NULL);
        if (ready_sockets_num == -1) {
            fprintf(stderr, ERR_STR "Unable to select sockets: %s" CLR_STR "\n", strerror(errno));
            return 1;
        }

        for (int i = 0; i < NUM_SOCKETS; i++) {
            if (FD_ISSET(SOCKETS[i], &read_socket_fds)) {
                pid_t child = client_handler(SOCKETS[i]);
                if (child == 0) {
                    return 0;
                } else if (child > 0) {
                    for (int j = 0; j < MAX_CHILDREN; j++) {
                        if (CHILDREN[j] == 0) {
                            CHILDREN[j] = child;
                        }
                    }
                }
            }
        }
    }
}
