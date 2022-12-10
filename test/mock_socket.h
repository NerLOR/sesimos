
#ifndef SESIMOS_MOCK_SOCKET_H
#define SESIMOS_MOCK_SOCKET_H

#include <stdlib.h>

#define MOCK_SOCKET_MODE_SUCCESS 0
#define MOCK_SOCKET_MODE_EINTR 1
#define MOCK_SOCKET_MODE_CLOSED 2

#define socket(args...) mock_socket(args)
#define send(args...) mock_send(args)

extern int mock_socket_send_mode;

int mock_socket(int domain, int type, int protocol);

ssize_t mock_send(int fd, const void *buf, size_t n, int flags);

#endif //SESIMOS_MOCK_SOCKET_H
