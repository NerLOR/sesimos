
#include <stdio.h>
#include <errno.h>

#include "mock_socket.h"

int mock_socket_send_mode;

static int sockets[256] = {0};
static int n_sockets = 0;

int mock_socket(int domain, int type, int protocol) {
    printf("SOCKET\n");
    return (n_sockets++) + 100;
}

ssize_t mock_send(int fd, const void *buf, size_t n, int flags) {
    printf("SEND\n");
    if (mock_socket_send_mode == MOCK_SOCKET_MODE_EINTR) {
        errno = EINTR;
        return rand() % ((ssize_t) n) - 1;
    } else if (mock_socket_send_mode == MOCK_SOCKET_MODE_CLOSED) {
        errno = 0; // TODO
        return -1;
    }

    return (ssize_t) n;
}
