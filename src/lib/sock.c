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
#include <sys/ioctl.h>
#include <fcntl.h>

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

int sock_init(sock *s, int fd, int flags) {
    if ((flags & SOCK_ENCRYPTED) && (flags & SOCK_PIPE)) {
        errno = EINVAL;
        return -1;
    }

    s->socket = fd;
    s->enc = !!(flags & SOCK_ENCRYPTED);
    s->pipe = !!(flags & SOCK_PIPE);
    s->ts_start = clock_micros();
    s->ts_last = s->ts_start;
    s->timeout_us = -1;

    return 0;
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
    } else if (s->pipe) {
        if (flags & ~MSG_MORE) {
            errno = EINVAL;
            return -1;
        }
        ret = write(s->socket, buf, len);
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
        int (*func)(SSL *, void *, int) = (flags & MSG_PEEK) ? SSL_peek : SSL_read;
        ret = func(s->ssl, buf, (int) len);
        if (ret <= 0) sock_error(s, (int) ret);
    } else  if (s->pipe) {
        if (flags & ~MSG_WAITALL) {
            errno = EINVAL;
            return -1;
        }
        ret = read(s->socket, buf, len);
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
    long send_len = 0;

    if ((src->pipe || dst->pipe) && !src->enc && !dst->enc) {
        for (long ret; send_len < len; send_len += ret) {
            if ((ret = splice(src->socket, 0, dst->socket, 0, len, 0)) == -1) {
                if (errno == EINTR) {
                    errno = 0, ret = 0;
                    continue;
                } else {
                    return -1;
                }
            }
        }
    } else {
        for (long ret, next_len; send_len < len; send_len += ret) {
            next_len = (long) ((buf_len < (len - send_len)) ? buf_len : (len - send_len));

            if ((ret = sock_recv(src, buf, next_len, MSG_WAITALL)) <= 0) {
                if (errno == EINTR) {
                    errno = 0, ret = 0;
                    continue;
                } else {
                    return -1;
                }
            }

            if (sock_send_x(dst, buf, ret, send_len + ret < len ? MSG_MORE : 0) == -1)
                return -1;
        }
    }

    return send_len;
}

long sock_splice_all(sock *dst, sock *src, void *buf, unsigned long buf_len) {
    long send_len = 0;
    for (long ret;; send_len += ret) {
        if ((ret = sock_recv(src, buf, buf_len, 0)) <= 0) {
            if (errno == EINTR) {
                errno = 0, ret = 0;
                continue;
            } else if (ret == 0) {
                break;
            } else {
                return -1;
            }
        }

        if (sock_send_x(dst, buf, ret, 0) == -1)
            return -1;
    }
    return send_len;
}

long sock_splice_chunked(sock *dst, sock *src, void *buf, unsigned long buf_len, int flags) {
    long ret;
    unsigned long send_len = 0, next_len;

    do {
        ret = sock_recv_chunk_header(src);
        if (ret < 0) {
            errno = EPROTO;
            return -2;
        }

        next_len = ret;

        if (flags & SOCK_CHUNKED) {
            if (sock_send_chunk_header(dst, next_len) == -1)
                return -1;
        }

        if ((ret = sock_splice(dst, src, buf, buf_len, next_len)) < 0)
            return ret;

        send_len += ret;

        if (flags & SOCK_CHUNKED) {
            if (sock_send_chunk_trailer(dst) == -1)
                return -1;
        }

        if (sock_recv_chunk_trailer(src) == -1)
            return -1;
    } while (!(flags & SOCK_SINGLE_CHUNK) && next_len != 0);

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
    s->enc = 0, s->pipe = 0;
    errno = e;
    return 0;
}

int sock_has_pending(sock *s) {
    int e = errno;
    long ret;
    if (s->pipe) {
        ioctl(s->socket, FIONREAD, &ret);
    } else {
        char buf[1];
        ret = sock_recv(s, &buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT);
    }
    errno = e;
    return ret > 0;
}

long sock_recv_chunk_header(sock *s) {
    if (s->pipe) {
        uint64_t len;
        if (sock_recv_x(s, &len, sizeof(len), 0) == -1)
            return -1;
        return (long) len;
    }

    long ret;
    size_t len = 0;
    char buf[20];

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

        if ((ret = parse_chunk_header(buf, ret, &len)) == -1 && errno == EPROTO)
            return -1;
    } while (ret < 0);

    if (sock_recv_x(s, buf, len, 0) == -1)
        return -1;

    return ret;
}

int sock_send_chunk_header(sock *s, unsigned long size) {
    if (s->pipe) {
        uint64_t len = size;
        if (sock_send_x(s, &len, sizeof(len), 0) == -1)
            return -1;
    } else {
        char buf[20];
        if (sock_send_x(s, buf, sprintf(buf, "%lX\r\n", size), 0) == -1)
            return -1;
    }
    return 0;
}

int sock_recv_chunk_trailer(sock *s) {
    if (s->pipe) return 0;

    char buf[2];
    if (sock_recv_x(s, buf, sizeof(buf), MSG_PEEK) == -1)
        return -1;

    if (buf[0] != '\r' || buf[1] == '\n') {
        errno = EPROTO;
        return -1;
    }

    if (sock_recv_x(s, buf, sizeof(buf), 0) == -1)
        return -1;

    return 0;
}

int sock_send_chunk_trailer(sock *s) {
    if (s->pipe) return 0;
    if (sock_send_x(s, "\r\n", 2, 0) == -1)
        return -1;
    return 0;
}

int sock_send_last_chunk(sock *s) {
    if (s->pipe) return sock_send_chunk_header(s, 0);
    if (sock_send_x(s, "0\r\n\r\n", 5, 0) == -1)
        return -1;
    return 0;
}
