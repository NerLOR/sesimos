/**
 * Sesimos - secure, simple, modern web server
 * @brief Async handler
 * @file src/async.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "async.h"
#include "logger.h"
#include "lib/list.h"
#include "lib/utils.h"

#include <poll.h>
#include <sys/epoll.h>
#include <signal.h>
#include <errno.h>
#include <memory.h>
#include <pthread.h>
#include <semaphore.h>
#include <unistd.h>

#define ASYNC_MAX_EVENTS 16

typedef struct {
    int fd;
    sock *socket;
    async_evt_t events;
    int flags;
    void *arg;
    void (*cb)(void *);
    void (*to_cb)(void *);
    void (*err_cb)(void *);
} evt_listen_t;

typedef struct {
    int n;
    evt_listen_t *q[ASYNC_MAX_EVENTS];
} listen_queue_t;

static volatile listen_queue_t listen1, listen2, *listen_q = &listen1;
static volatile sig_atomic_t alive = 1;
static pthread_t thread = -1;
static sem_t lock;
static int epoll_fd;

static short async_a2p(async_evt_t events) {
    short ret = 0;
    if (events & ASYNC_IN)  ret |= POLLIN;
    if (events & ASYNC_PRI) ret |= POLLPRI;
    if (events & ASYNC_OUT) ret |= POLLOUT;
    if (events & ASYNC_ERR) ret |= POLLERR;
    if (events & ASYNC_HUP) ret |= POLLHUP;
    if (events & ASYNC_RDNORM) ret |= POLLRDNORM;
    if (events & ASYNC_RDBAND) ret |= POLLRDBAND;
    if (events & ASYNC_WRNORM) ret |= POLLWRNORM;
    if (events & ASYNC_WRBAND) ret |= POLLWRBAND;
    if (events & ASYNC_MSG) ret |= POLLMSG;
    return ret;
}

static unsigned int async_a2e(async_evt_t events) {
    unsigned int ret = 0;
    if (events & ASYNC_IN)  ret |= EPOLLIN;
    if (events & ASYNC_PRI) ret |= EPOLLPRI;
    if (events & ASYNC_OUT) ret |= EPOLLOUT;
    if (events & ASYNC_ERR) ret |= EPOLLERR;
    if (events & ASYNC_HUP) ret |= EPOLLHUP;
    if (events & ASYNC_RDNORM) ret |= EPOLLRDNORM;
    if (events & ASYNC_RDBAND) ret |= EPOLLRDBAND;
    if (events & ASYNC_WRNORM) ret |= EPOLLWRNORM;
    if (events & ASYNC_WRBAND) ret |= EPOLLWRBAND;
    if (events & ASYNC_MSG) ret |= EPOLLMSG;
    return ret;
}

static async_evt_t async_p2a(short events) {
    async_evt_t ret = 0;
    if (events & POLLIN)   ret |= ASYNC_IN;
    if (events & POLLPRI)  ret |= ASYNC_PRI;
    if (events & POLLOUT)  ret |= ASYNC_OUT;
    if (events & POLLERR)  ret |= ASYNC_ERR;
    if (events & POLLHUP)  ret |= ASYNC_HUP;
    if (events & POLLRDNORM) ret |= ASYNC_RDNORM;
    if (events & POLLRDBAND) ret |= ASYNC_RDBAND;
    if (events & POLLWRNORM) ret |= ASYNC_WRNORM;
    if (events & POLLWRBAND) ret |= ASYNC_WRBAND;
    if (events & POLLMSG) ret |= ASYNC_MSG;
    return ret;
}

static async_evt_t async_e2a(unsigned int events) {
    async_evt_t ret = 0;
    if (events & EPOLLIN)   ret |= ASYNC_IN;
    if (events & EPOLLPRI)  ret |= ASYNC_PRI;
    if (events & EPOLLOUT)  ret |= ASYNC_OUT;
    if (events & EPOLLERR)  ret |= ASYNC_ERR;
    if (events & EPOLLHUP)  ret |= ASYNC_HUP;
    if (events & EPOLLRDNORM) ret |= ASYNC_RDNORM;
    if (events & EPOLLRDBAND) ret |= ASYNC_RDBAND;
    if (events & EPOLLWRNORM) ret |= ASYNC_WRNORM;
    if (events & EPOLLWRBAND) ret |= ASYNC_WRBAND;
    if (events & EPOLLMSG) ret |= ASYNC_MSG;
    return ret;
}

static short async_e2p(unsigned int events) {
    return async_a2p(async_e2a(events));
}

static unsigned int async_p2e(short events) {
    return async_a2e(async_p2a(events));
}

static int async_add_to_queue(evt_listen_t *evt) {
    while (sem_wait(&lock) != 0) {
        if (errno == EINTR) {
            errno = 0;
            continue;
        } else {
            return -1;
        }
    }

    evt_listen_t *ptr = malloc(sizeof(evt_listen_t));
    if (ptr == NULL) {
        sem_post(&lock);
        return -1;
    }

    memcpy(ptr, evt, sizeof(*evt));
    listen_q->q[listen_q->n++] = ptr;

    sem_post(&lock);

    return 0;
}

static int async_exec(evt_listen_t *evt, async_evt_t r_events) {
    int ret, e = errno;
    if (r_events & evt->events) {
        // specified event(s) occurred
        if (!(evt->flags & ASYNC_IGNORE_PENDING) && evt->socket && !sock_has_pending(evt->socket, 0)) {
            evt->err_cb(evt->arg);
            ret = 0;
        } else {
            evt->cb(evt->arg);
            ret = (evt->flags & ASYNC_KEEP) ? 1 : 0;
        }
    } else if (r_events & (POLLERR | POLLHUP | POLLNVAL)) {
        // error occurred
        evt->err_cb(evt->arg);
        ret = 0;
    } else {
        // no event occurred
        ret = -1;
    }

    errno = e;
    return ret;
}

static int async_check(evt_listen_t *evt) {
    struct pollfd fds[1] = {{
        .fd = evt->fd,
        .events = async_a2p(evt->events)
    }};

    // check, if fd is already ready
    switch (poll(fds, 1, 0)) {
        case 1:
            // fd already ready
            if (async_exec(evt, async_p2a(fds[0].revents)) == 0)
                return 1;
            break;
        case -1:
            error("Unable to poll");
            return -1;
    }

    return 0;
}

static int async_add(evt_listen_t *evt) {
    if (async_check(evt) == 1)
        return 0;

    int ret = async_add_to_queue(evt);
    if (ret == 0 && thread != -1)
        pthread_kill(thread, SIGUSR1);

    return ret;
}

int async_fd(int fd, async_evt_t events, int flags, void *arg, void cb(void *), void to_cb(void *), void err_cb(void *)) {
    evt_listen_t evt = {
            .fd = fd,
            .socket = NULL,
            .events = events,
            .flags = flags,
            .arg = arg,
            .cb = cb,
            .to_cb = to_cb,
            .err_cb = err_cb,
    };
    return async_add(&evt);
}

int async(sock *s, async_evt_t events, int flags, void *arg, void cb(void *), void to_cb(void *), void err_cb(void *)) {
    evt_listen_t evt = {
            .fd = s->socket,
            .socket = s,
            .events = events,
            .flags = flags,
            .arg = arg,
            .cb = cb,
            .to_cb = to_cb,
            .err_cb = err_cb,
    };
    return async_add(&evt);
}

int async_init(void) {
    if (sem_init(&lock, 0, 1) != 0) {
        return -1;
    }

    listen1.n = 0;
    listen2.n = 0;

    if ((epoll_fd = epoll_create1(0)) == -1) {
        async_free();
        return -1;
    }

    return 0;
}

void async_free(void) {
    int e = errno;
    sem_destroy(&lock);
    close(epoll_fd);
    errno = e;
}

void async_thread(void) {
    struct epoll_event ev, events[ASYNC_MAX_EVENTS];
    int num_fds;
    long ts, min_ts, cur_ts;
    volatile listen_queue_t *l;
    evt_listen_t **local;

    if ((local = list_create(sizeof(evt_listen_t *), 16)) == NULL) {
        critical("Unable to create async local list");
        return;
    }

    thread = pthread_self();

    // main event loop
    while (alive) {
        // swap listen queue
        while (sem_wait(&lock) != 0) {
            if (errno == EINTR) {
                errno = 0;
                continue;
            } else {
                critical("Unable to lock async queue");
                return;
            }
        }
        l = listen_q;
        listen_q = (listen_q == &listen1) ? &listen2 : &listen1;
        sem_post(&lock);

        // fill local list and epoll instance with previously added queue entries
        for (int i = 0; i < l->n; i++) {
            evt_listen_t *evt = l->q[i];
            local = list_append(local, &evt);
            if (local == NULL) {
                critical("Unable to resize async local list");
                return;
            }

            ev.events = async_a2e(evt->events);
            ev.data.ptr = evt;

            while (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, evt->fd, &ev) == -1) {
                if (errno == EEXIST) {
                    // fd already exists, delete old one
                    warning("Unable to add file descriptor to epoll instance");
                    errno = 0;
                    if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, evt->fd, NULL) != -1)
                        continue;
                } else if (errno == EBADF) {
                    // fd probably already closed
                    warning("Unable to add file descriptor to epoll instance");
                    errno = 0;
                    local = list_delete(local, &evt);
                    if (local == NULL) {
                        critical("Unable to resize async local list");
                        return;
                    }
                    break;
                }
                critical("Unable to add file descriptor to epoll instance");
                return;
            }
        }
        // reset size of queue
        l->n = 0;

        // TODO timeout calculation = O(n)
        // calculate wait timeout
        min_ts = -1000, cur_ts = clock_micros();
        for (int i = 0; i < list_size(local); i++) {
            evt_listen_t *evt = local[i];
            if (!evt->socket || evt->socket->timeout_us < 0) continue;

            ts = evt->socket->ts_last + evt->socket->timeout_us - cur_ts;
            if (min_ts == -1000 || ts < min_ts) min_ts = ts;
        }

        // epoll is used in level-triggered mode, so buffers are taken into account
        if ((num_fds = epoll_wait(epoll_fd, events, ASYNC_MAX_EVENTS, (int) (min_ts / 1000))) == -1) {
            if (errno == EINTR) {
                // interrupt
                errno = 0;
                continue;
            } else {
                // other error
                critical("Unable to poll for events");
                return;
            }
        }

        for (int i = 0; i < num_fds; i++) {
            evt_listen_t *evt = events[i].data.ptr;
            if (!list_contains(local, &evt)) continue;

            if (async_exec(evt, async_e2a(events[i].events)) == 0) {
                logger_set_prefix("");
                if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, evt->fd, NULL) == -1) {
                    if (errno == EBADF || errno == ENOENT) {
                        // already closed fd or not found, do not die
                        warning("Unable to remove file descriptor from epoll instance");
                        errno = 0;
                    } else {
                        critical("Unable to remove file descriptor from epoll instance");
                        return;
                    }
                }

                local = list_delete(local, &evt);
                if (local == NULL) {
                    critical("Unable to resize async local list");
                    return;
                }

                free(evt);
            }
            logger_set_prefix("");
        }

        // check, if some socket ran into a timeout
        cur_ts = clock_micros();
        for (int i = 0; i < list_size(local); i++) {
            evt_listen_t *evt = local[i];
            if (!evt->socket) continue;

            if (evt->socket->timeout_us >= 0 && (cur_ts - evt->socket->ts_last) >= evt->socket->timeout_us) {
                evt->to_cb(evt->arg);

                if (epoll_ctl(epoll_fd, EPOLL_CTL_DEL, evt->fd, NULL) == -1) {
                    if (errno == EBADF || errno == ENOENT) {
                        // already closed fd or not found, do not die
                        warning("Unable to remove file descriptor from epoll instance");
                        errno = 0;
                    } else {
                        critical("Unable to remove file descriptor from epoll instance");
                        return;
                    }
                }

                local = list_remove(local, i--);
            }
        }
        logger_set_prefix("");
        errno = 0;
    }

    // cleanup
    for (int i = 0; i < list_size(local); i++) {
        free(local[i]);
    }
    list_free(local);
}

void async_stop(void) {
    alive = 0;
}
