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

typedef struct {
    int fd;
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

static listen_queue_t listen1, listen2, *listen = &listen1;
static volatile sig_atomic_t alive = 1;
static pthread_t thread = -1;

static int async_add_to_queue(evt_listen_t *evt) {
    // TODO locking
    memcpy(&listen->q[listen->n++], evt, sizeof(*evt));
    return 0;
}

int async(int fd, short events, int flags, void cb(void *), void *arg, void err_cb(void *), void *err_arg) {
    struct pollfd fds[1] = {{.fd = fd, .events = events}};
    evt_listen_t evt = {
            .fd = fd,
            .events = events,
            .flags = flags,
            .cb = cb,
            .arg = arg,
            .err_cb = err_cb,
            .err_arg = err_arg,
    };

    // check, if fd is already ready
    if (poll(fds, 1, 0) == 1) {
        // fd already read
        if (fds[0].revents & events) {
            // specified event(s) occurred
            cb(arg);

            if (!(flags & ASYNC_KEEP))
                return 0;
        } else if (fds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            // error occurred
            err_cb(err_arg);
            return 0;
        }
    }

    int ret = async_add_to_queue(&evt);
    if (ret == 0 && thread != -1)
        pthread_kill(thread, SIGUSR1);

    return ret;
}

void async_thread(void) {
    int num_fds;
    struct pollfd fds[256];  // TODO dynamic

    thread = pthread_self();

    // main event loop
    while (alive) {
        // swap listen queue
        listen_queue_t *l = listen;
        listen = (listen == &listen1) ? &listen2 : &listen1;

        // fill fds with newly added queue entries
        for (num_fds = 0; num_fds < l->n; num_fds++) {
            fds[num_fds].fd = l->q[num_fds].fd;
            fds[num_fds].events = l->q[num_fds].events;
        }

        if (poll(fds, num_fds, -1) < 0) {
            if (errno == EINTR) {
                // interrupt
                errno = 0;
            } else {
                // other error
                critical("Unable to poll for events");
                return;
            }
        }

        for (int i = 0; i < num_fds; i++) {
            evt_listen_t *e = &l->q[i];
            if (fds[i].revents & e->events) {
                // specified event(s) occurred
                e->cb(e->arg);

                if (e->flags & ASYNC_KEEP)
                    async_add_to_queue(e);
            } else if (fds[i].revents & (POLLERR | POLLHUP | POLLNVAL)) {
                // error occurred
                e->err_cb(e->err_arg);
            } else {
                // no event occurred
                async_add_to_queue(e);
            }

            // reset errno to prevent strange behaviour
            errno = 0;
        }

        // reset size of queue
        l->n = 0;
    }
}

void async_stop(void) {
    alive = 0;
}
