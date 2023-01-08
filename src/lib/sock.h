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

typedef struct {
    unsigned int enc:1;
    int socket;
    union {
        struct sockaddr sock;
        struct sockaddr_in6 ipv6;
    } _addr;
    char *addr, *s_addr;
    SSL_CTX *ctx;
    SSL *ssl;
    long ts_start, ts_last, timeout_us;
    long _last_ret;
    int _errno;
    unsigned long _ssl_error;
} sock;

int sock_enc_error(sock *s);

const char *sock_strerror(sock *s);

int sock_set_socket_timeout_micros(sock *s, long recv_micros, long send_micros);

int sock_set_socket_timeout(sock *s, double sec);

int sock_set_timeout_micros(sock *s, long micros);

int sock_set_timeout(sock *s, double sec);

long sock_send(sock *s, void *buf, unsigned long len, int flags);

long sock_recv(sock *s, void *buf, unsigned long len, int flags);

long sock_splice(sock *dst, sock *src, void *buf, unsigned long buf_len, unsigned long len);

long sock_splice_chunked(sock *dst, sock *src, void *buf, unsigned long buf_len);

int sock_close(sock *s);

int sock_has_pending(sock *s);

long sock_parse_chunk_header(const char *buf, long len, long *ret_len);

long sock_get_chunk_header(sock *s);

#endif //SESIMOS_SOCK_H
