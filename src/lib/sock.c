/**
 * sesimos - secure, simple, modern web server
 * @brief Basic TCP and TLS socket
 * @file src/lib/sock.c
 * @author Lorenz Stechauner
 * @date 2021-01-07
 */

#include "sock.h"
#include "utils.h"
#include "error.h"

#include <errno.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <openssl/err.h>

static void ssl_error(unsigned long err) {
    if (err == SSL_ERROR_NONE) {
        errno = 0;
    } else if (err == SSL_ERROR_SYSCALL) {
        // errno already set
    } else if (err == SSL_ERROR_SSL) {
        error_ssl_err(ERR_get_error());
    } else {
        error_ssl(err);
    }
}

void sock_error(sock *s, int ret) {
    ssl_error(SSL_get_error(s->ssl, ret));
}

const char *sock_error_str(unsigned long err) {
    switch (err) {
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
        case SSL_ERROR_WANT_ASYNC:
            return "want async";
        case SSL_ERROR_WANT_ASYNC_JOB:
            return "want async job";
        case SSL_ERROR_WANT_CLIENT_HELLO_CB:
            return "want client hello callback";
            //case SSL_ERROR_WANT_RETRY_VERIFY:
            //    return "want retry verify";
        default:
            return "unknown error";
    }
}

int sock_set_socket_timeout_micros(sock *s, long recv_micros, long send_micros) {
    struct timeval recv_to = {.tv_sec = recv_micros / 1000000, .tv_usec = recv_micros % 1000000},
                   send_to = {.tv_sec = send_micros / 1000000, .tv_usec = send_micros % 1000000};

    if (setsockopt(s->socket, SOL_SOCKET, SO_RCVTIMEO, &recv_to, sizeof(recv_to)) != 0)
        return -1;

    if (setsockopt(s->socket, SOL_SOCKET, SO_SNDTIMEO, &send_to, sizeof(send_to)) != 0)
        return -1;

    return 0;
}

int sock_set_socket_timeout(sock *s, double sec) {
    return sock_set_socket_timeout_micros(s, (long) (sec * 1000000L), (long) (sec * 1000000L));
}

int sock_set_timeout_micros(sock *s, long micros) {
    if (micros < 0)
        return -1;

    s->timeout_us = micros;
    return 0;
}

int sock_set_timeout(sock *s, double sec) {
    return sock_set_timeout_micros(s, (long) (sec * 1000000));
}

long sock_send(sock *s, void *buf, unsigned long len, int flags) {
    if (s->socket == 0) {
        errno = ENOTCONN;
        return -1;
    }

    long ret;
    if (s->enc) {
        ret = SSL_write(s->ssl, buf, (int) len);
        if (ret <= 0) sock_error(s, (int) ret);
    } else {
        ret = send(s->socket, buf, len, flags);
    }

    if (ret >= 0) {
        s->ts_last = clock_micros();
        return ret;
    } else {
        return -1;
    }
}

long sock_send_x(sock *s, void *buf, unsigned long len, int flags) {
    for (long ret, sent = 0; sent < len; sent += ret) {
        if ((ret = sock_send(s, (unsigned char *) buf + sent, len - sent, flags)) <= 0) {
            if (errno == EINTR) {
                errno = 0, ret = 0;
                continue;
            } else {
                return -1;
            }
        }
    }
    return (long) len;
}

long sock_recv(sock *s, void *buf, unsigned long len, int flags) {
    if (s->socket == 0) {
        errno = ENOTCONN;
        return -1;
    }

    long ret;
    if (s->enc) {
        int (*func)(SSL*, void*, int) = (flags & MSG_PEEK) ? SSL_peek : SSL_read;
        ret = func(s->ssl, buf, (int) len);
        if (ret <= 0) sock_error(s, (int) ret);
    } else {
        ret = recv(s->socket, buf, len, flags);
    }

    if (ret >= 0) {
        s->ts_last = clock_micros();
        return ret;
    } else {
        return -1;
    }
}

long sock_recv_x(sock *s, void *buf, unsigned long len, int flags) {
    for (long ret, rcv = 0; rcv < len; rcv += ret) {
        if ((ret = sock_recv(s, (unsigned char *) buf + rcv, len - rcv, flags | MSG_WAITALL)) <= 0) {
            if (errno == EINTR) {
                errno = 0, ret = 0;
                continue;
            } else {
                return -1;
            }
        }
    }
    return (long) len;
}

long sock_splice(sock *dst, sock *src, void *buf, unsigned long buf_len, unsigned long len) {
    long ret;
    unsigned long send_len = 0;
    unsigned long next_len;
    while (send_len < len) {
        next_len = (buf_len < (len - send_len)) ? buf_len : (len - send_len);
        ret = sock_recv(src, buf, next_len, 0);
        if (ret <= 0) return -2;
        next_len = ret;
        ret = sock_send(dst, buf, next_len, send_len + next_len < len ? MSG_MORE : 0);
        if (ret < 0) return -1;
        if (ret != next_len) return -3;
        send_len += next_len;
    }
    return (long) send_len;
}

long sock_splice_chunked(sock *dst, sock *src, void *buf, unsigned long buf_len, int flags) {
    long ret;
    unsigned long send_len = 0, next_len;

    while (!(flags & SOCK_SINGLE_CHUNK)) {
        ret = sock_get_chunk_header(src);
        if (ret < 0) return -2;

        next_len = ret;

        if (flags & SOCK_CHUNKED) {
            ret = sprintf(buf, "%lX\r\n", next_len);
            if (sock_send_x(dst, buf, ret, 0) == -1)
                return -1;
        }

        if (next_len == 0)
            break;

        if ((ret = sock_splice(dst, src, buf, buf_len, next_len)) < 0)
            return ret;

        send_len += ret;

        if (flags & SOCK_CHUNKED) {
            if (sock_send_x(dst, "\r\n", 2, 0) == -1)
                return -1;
        }

        if (sock_recv_x(src, buf, 2, 0) == -1)
            return -1;
    }

    return (long) send_len;
}

int sock_close(sock *s) {
    int e = errno;
    if (s->enc && s->ssl != NULL) {
        SSL_shutdown(s->ssl);
        SSL_free(s->ssl);
        s->ssl = NULL;
    }
    close(s->socket);
    s->socket = 0;
    s->enc = 0;
    errno = e;
    return 0;
}

int sock_has_pending(sock *s) {
    char buf[1];
    int e = errno;
    long ret = sock_recv(s, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
    errno = e;
    return ret == 1;
}

long sock_parse_chunk_header(const char *buf, long len, long *ret_len) {
    for (int i = 0; i < len; i++) {
        char ch = buf[i];
        if (ch == '\r') {
            continue;
        } else if (ch == '\n') {
            if (ret_len != NULL) *ret_len = i + 1;
            return strtol(buf, NULL, 16);
        } else if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) {
            return -2;
        }
    }

    return -1;
}

long sock_get_chunk_header(sock *s) {
    long ret, len;
    char buf[16];

    do {
        if ((ret = sock_recv(s, buf, sizeof(buf) - 1, MSG_PEEK)) <= 0) {
            if (errno == EINTR) {
                errno = 0;
                continue;
            } else {
                return -1;
            }
        } else if (ret < 2) {
            continue;
        }
        buf[ret] = 0;

        if ((ret = sock_parse_chunk_header(buf, ret, &len)) == -2)
            return -1;
    } while (ret < 0);

    if (sock_recv_x(s, buf, len, 0) == -1)
        return -1;

    return ret;
}
