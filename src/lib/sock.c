/**
 * sesimos - secure, simple, modern web server
 * @brief Basic TCP and TLS socket
 * @file src/lib/sock.c
 * @author Lorenz Stechauner
 * @date 2021-01-07
 */

#include "sock.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <poll.h>


int sock_enc_error(sock *s) {
    return (int) s->enc ? SSL_get_error(s->ssl, (int) s->_last_ret) : 0;
}

const char *sock_strerror(sock *s) {
    if (s->_last_ret == 0) {
        return "closed";
    } else if (s->enc) {
        if (s->_last_ret > 0) {
            return NULL;
        }
        const char *err1 = ERR_reason_error_string(s->_ssl_error);
        const char *err2 = strerror(errno);
        switch (sock_enc_error(s)) {
            case SSL_ERROR_NONE:
                return NULL;
            case SSL_ERROR_ZERO_RETURN:
                return "closed";
            case SSL_ERROR_WANT_READ:
                return "want read";
            case SSL_ERROR_WANT_WRITE:
                return "want write";
            case SSL_ERROR_WANT_CONNECT:
                return "want connect";
            case SSL_ERROR_WANT_ACCEPT:
                return "want accept";
            case SSL_ERROR_WANT_X509_LOOKUP:
                return "want x509 lookup";
            case SSL_ERROR_SYSCALL:
                return ((s->_ssl_error == 0) ? ((s->_last_ret == 0) ? "protocol violation" : err2) : err1);
            case SSL_ERROR_SSL:
                return err1;
            default:
                return "unknown error";
        }
    } else {
        return strerror(s->_errno);
    }
}

long sock_send(sock *s, void *buf, unsigned long len, int flags) {
    long ret;
    if (s->enc) {
        ret = SSL_write(s->ssl, buf, (int) len);
        s->_ssl_error = ERR_get_error();
    } else {
        ret = send(s->socket, buf, len, flags);
    }
    s->_last_ret = ret;
    s->_errno = errno;
    return ret >= 0 ? ret : -1;
}

long sock_recv(sock *s, void *buf, unsigned long len, int flags) {
    long ret;
    if (s->enc) {
        if (flags & MSG_PEEK) {
            ret = SSL_peek(s->ssl, buf, (int) len);
        } else {
            ret = SSL_read(s->ssl, buf, (int) len);
        }
        s->_ssl_error = ERR_get_error();
    } else {
        ret = recv(s->socket, buf, len, flags);
    }
    s->_last_ret = ret;
    s->_errno = errno;
    return ret >= 0 ? ret : -1;
}

long sock_splice(sock *dst, sock *src, void *buf, unsigned long buf_len, unsigned long len) {
    long ret;
    unsigned long send_len = 0;
    unsigned long next_len;
    while (send_len < len) {
        next_len = (buf_len < (len - send_len)) ? buf_len : (len - send_len);
        ret = sock_recv(src, buf, next_len, 0);
        if (ret < 0) return -2;
        next_len = ret;
        ret = sock_send(dst, buf, next_len, send_len + next_len < len ? MSG_MORE : 0);
        if (ret < 0) return -1;
        if (ret != next_len) return -3;
        send_len += next_len;
    }
    return (long) send_len;
}

int sock_close(sock *s) {
    if ((int) s->enc && s->ssl != NULL) {
        if (s->_last_ret >= 0) SSL_shutdown(s->ssl);
        SSL_free(s->ssl);
        s->ssl = NULL;
    }
    shutdown(s->socket, SHUT_RDWR);
    close(s->socket);
    s->socket = 0;
    s->enc = 0;
    return 0;
}

int sock_check(sock *s) {
    char buf;
    return recv(s->socket, &buf, 1, MSG_PEEK | MSG_DONTWAIT) == 1;
}

int sock_poll(sock *sockets[], sock *ready[], sock *error[], int n_sock, int *n_ready, int *n_error, short events, int timeout_ms) {
    struct pollfd fds[n_sock];
    for (int i = 0; i < n_sock; i++) {
        fds[i].fd = sockets[i]->socket;
        fds[i].events = events;
    }

    int ret = poll(fds, n_sock, timeout_ms);
    if (ret < 0 || ready == NULL || error == NULL) return ret;

    *n_ready = 0, *n_error = 0;
    for (int i = 0; i < n_sock; i++) {
        if (fds[i].revents & events)
            ready[(*n_ready)++] = sockets[i];
        if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL))
            error[(*n_error)++] = sockets[i];
    }

    return ret;
}

int sock_poll_read(sock *sockets[], sock *readable[], sock *error[], int n_sock, int *n_readable, int *n_error, int timeout_ms) {
    return sock_poll(sockets, readable, error, n_sock, n_readable, n_error, POLLIN, timeout_ms);
}

int sock_poll_write(sock *sockets[], sock *writable[], sock *error[], int n_sock, int *n_writable, int *n_error, int timeout_ms) {
    return sock_poll(sockets, writable, error, n_sock, n_writable, n_error, POLLOUT, timeout_ms);
}
