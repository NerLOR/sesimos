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

typedef struct {
    unsigned int enc:1;
    int socket;
    SSL_CTX *ctx;
    SSL *ssl;
    long _last_ret;
    int _errno;
    unsigned long _ssl_error;
} sock;

int sock_enc_error(sock *s);

const char *sock_strerror(sock *s);

long sock_send(sock *s, void *buf, unsigned long len, int flags);

long sock_recv(sock *s, void *buf, unsigned long len, int flags);

long sock_splice(sock *dst, sock *src, void *buf, unsigned long buf_len, unsigned long len);

long sock_splice_chunked(sock *dst, sock *src, void *buf, unsigned long buf_len);

int sock_close(sock *s);

int sock_check(sock *s);

int sock_poll(sock *sockets[], sock *ready[], sock *error[], int n_sock, int *n_ready, int *n_error, short events, int timeout_ms);

int sock_poll_read(sock *sockets[], sock *readable[], sock *error[], int n_sock, int *n_readable, int *n_error, int timeout_ms);

int sock_poll_write(sock *sockets[], sock *writable[], sock *error[], int n_sock, int *n_writable, int *n_error, int timeout_ms);

long sock_parse_chunk_header(const char *buf, long len, long *ret_len);

long sock_get_chunk_header(sock *s);

#endif //SESIMOS_SOCK_H
