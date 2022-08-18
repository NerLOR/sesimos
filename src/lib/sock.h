/**
 * Necronda Web Server
 * Basic TCP and TLS socket (header file)
 * src/lib/sock.h
 * Lorenz Stechauner, 2021-01-07
 */

#ifndef NECRONDA_SERVER_SOCK_H
#define NECRONDA_SERVER_SOCK_H

#include <openssl/crypto.h>
#include <sys/socket.h>

typedef struct {
    unsigned int enc:1;
    int socket;
    SSL_CTX *ctx;
    SSL *ssl;
    char *buf;
    unsigned long buf_len;
    unsigned long buf_off;
    long _last_ret;
    int _errno;
    unsigned long _ssl_error;
} sock;

int sock_enc_error(sock *s);

const char *sock_strerror(sock *s);

long sock_send(sock *s, void *buf, unsigned long len, int flags);

long sock_recv(sock *s, void *buf, unsigned long len, int flags);

long sock_splice(sock *dst, sock *src, void *buf, unsigned long buf_len, unsigned long len);

int sock_close(sock *s);

int sock_check(sock *s);

int sock_poll(sock *sockets[], sock *readable[], short events, int n_sock, int timeout_ms);

int sock_poll_read(sock *sockets[], sock *readable[], int n_sock, int timeout_ms);

int sock_poll_write(sock *sockets[], sock *writable[], int n_sock, int timeout_ms);

#endif //NECRONDA_SERVER_SOCK_H
