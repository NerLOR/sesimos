/**
 * Necronda Web Server
 * Basic TCP and TLS socket (header file)
 * src/sock.h
 * Lorenz Stechauner, 2021-01-07
 */

#ifndef NECRONDA_SERVER_SOCK_H
#define NECRONDA_SERVER_SOCK_H

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

const char *sock_strerror(sock *s);

long sock_send(sock *s, void *buf, unsigned long len, int flags);

long sock_recv(sock *s, void *buf, unsigned long len, int flags);

long sock_splice(sock *dst, sock *src, void *buf, unsigned long buf_len, unsigned long len);

#endif //NECRONDA_SERVER_SOCK_H
