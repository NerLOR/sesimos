/**
 * Sesimos - secure, simple, modern web server
 * @brief Async handler
 * @file src/async.c
 * @author Lorenz Stechauner
 * @date 2022-12-28
 */

#include "async.h"
#include "logger.h"

#include <poll.h>
#include <signal.h>
#include <errno.h>
#include <memory.h>
#include <pthread.h>
#include <semaphore.h>

typedef struct {
    int fd;
    sock *socket;
    short events;
    int flags;
    void (*cb)(void *);
    void *arg;
    void (*err_cb)(void *);
    void *err_arg;
} evt_listen_t;

typedef struct {
    int n;
    evt_listen_t q[256];
} listen_queue_t;

static listen_queue_t listen1, listen2, *listen_q = &listen1;
static volatile sig_atomic_t alive = 1;
static pthread_t thread = -1;
static sem_t lock;

static int async_add_to_queue(evt_listen_t *evt) {
    try_again:
    if (sem_wait(&lock) != 0) {
        if (errno == EINTR) {
            goto try_again;
        } else {
            return -1;
        }
    }

    memcpy(&listen_q->q[listen_q->n++], evt, sizeof(*evt));

    sem_post(&lock);

    return 0;
}

static int async_exec(evt_listen_t *evt, short r_events) {
    int ret, e = errno;
    if (r_events & evt->events) {
        // specified event(s) occurred
        if (evt->socket && !sock_has_pending(evt->socket)) {
            evt->err_cb(evt->err_arg);
            ret = 0;
        } else {
            evt->cb(evt->arg);
            ret = (evt->flags & ASYNC_KEEP) ? 1 : 0;
        }
    } else if (r_events & (POLLERR | POLLHUP | POLLNVAL)) {
        // error occurred
        evt->err_cb(evt->err_arg);
        ret = 0;
    } else {
        // no event occurred
        ret = -1;
    }

    logger_set_prefix("");
    errno = e;
    return ret;
}

static int async_check(evt_listen_t *evt) {
    struct pollfd fds[1] = {{.fd = evt->fd, .events = evt->events}};

    // check, if fd is already ready
    if (poll(fds, 1, 0) == 1) {
        // fd already read
        if (async_exec(evt, fds[0].revents) == 0)
            return 1;
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

int async_fd(int fd, short events, int flags, void cb(void *), void *arg, void err_cb(void *), void *err_arg) {
    evt_listen_t evt = {
            .fd = fd,
            .socket = NULL,
            .events = events,
            .flags = flags,
            .cb = cb,
            .arg = arg,
            .err_cb = err_cb,
            .err_arg = err_arg,
    };
    return async_add(&evt);
}

int async(sock *s, short events, int flags, void cb(void *), void *arg, void err_cb(void *), void *err_arg) {
    evt_listen_t evt = {
            .fd = s->socket,
            .socket = s,
            .events = events,
            .flags = flags,
            .cb = cb,
            .arg = arg,
            .err_cb = err_cb,
            .err_arg = err_arg,
    };
    return async_add(&evt);
}

int async_init(void) {
    if (sem_init(&lock, 0, 1) != 0) {
        return -1;
    }

    listen1.n = 0;
    listen2.n = 0;

    return 0;
}

void async_free(void) {
    int e = errno;
    sem_destroy(&lock);
    errno = e;
}

void async_thread(void) {
    listen_queue_t local_q;
    struct pollfd fds[256];  // TODO dynamic

    thread = pthread_self();
    local_q.n = 0;

    // main event loop
    while (alive) {
        // swap listen queue
        listen_queue_t *l = listen_q;
        listen_q = (listen_q == &listen1) ? &listen2 : &listen1;
        int num_fds = 0;

        // fill fds with previously added queue entries
        for (int i = 0; i < l->n; i++, local_q.n++) {
            memcpy(&local_q.q[local_q.n], &l->q[i], sizeof(evt_listen_t));
        }

        // reset size of queue
        l->n = 0;

        // fill fds with newly added queue entries
        for (int i = 0; i < local_q.n; i++, num_fds++) {
            fds[num_fds].fd = local_q.q[i].fd;
            fds[num_fds].events = local_q.q[i].events;
        }

        if (poll(fds, num_fds, -1) < 0) {
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

        local_q.n = 0;
        for (int i = 0; i < num_fds; i++) {
            evt_listen_t *evt = &local_q.q[i];
            if (async_exec(evt, fds[i].revents) != 0)
                memcpy(&local_q.q[local_q.n++], evt, sizeof(*evt));
        }
    }
}

void async_stop(void) {
    alive = 0;
}
