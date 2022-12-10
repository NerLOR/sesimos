
#include <criterion/criterion.h>
#include "mock_socket.h"
#include "../src/lib/sock.h"


Test(sock, sock_send_1) {
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    sock s;
    s.enc = 0;
    s.socket = fd;

    long ret = sock_send(&s, "Hello", 5, 0);
    cr_assert_eq(ret, 5);
}
