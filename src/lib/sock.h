/**
 * sesimos - secure, simple, modern web server
 * @brief Basic TCP and TLS socket (header file)
 * @file src/lib/sock.h
 * @author Lorenz Stechauner
 * @date 2021-01-07
 */

#ifndef SESIMOS_SOCK_H
#define SESIMOS_SOCK_H

#include <openssl/crypto.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define SOCK_CHUNKED 1
#define SOCK_SINGLE_CHUNK 2

#define SOCK_ENCRYPTED 1
#define SOCK_PIPE 2

typedef struct {
    unsigned int enc:1, pipe:1;
    int socket;
    union {
        struct sockaddr sock;
        struct sockaddr_in6 ipv6;
    } _addr;
    char *addr, *s_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    long ts_start, ts_last, timeout_us;
} sock;

void sock_error(sock *s, int ret);

const char *sock_error_str(unsigned long err);

int sock_init(sock *s, int fd, int enc);

int sock_set_socket_timeout_micros(int fd, long recv_micros, long send_micros);

int sock_set_socket_timeout(sock *s, double sec);

int sock_set_timeout_micros(sock *s, long micros);

int sock_set_timeout(sock *s, double sec);

long sock_send(sock *s, void *buf, unsigned long len, int flags);

long sock_send_x(sock *s, void *buf, unsigned long len, int flags);

long sock_recv(sock *s, void *buf, unsigned long len, int flags);

long sock_recv_x(sock *s, void *buf, unsigned long len, int flags);

long sock_splice(sock *dst, sock *src, void *buf, unsigned long buf_len, unsigned long len);

long sock_splice_all(sock *dst, sock *src, void *buf, unsigned long buf_len);

long sock_splice_chunked(sock *dst, sock *src, void *buf, unsigned long buf_len, int flags);

int sock_close(sock *s);

int sock_has_pending(sock *s);

long sock_recv_chunk_header(sock *s);

int sock_send_chunk_header(sock *s, unsigned long size);

int sock_recv_chunk_trailer(sock *s);

int sock_send_chunk_trailer(sock *s);

int sock_send_last_chunk(sock *s);

#endif //SESIMOS_SOCK_H
