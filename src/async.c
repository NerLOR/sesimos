

#include "logger.h"

#include <stdio.h>
#include <poll.h>
#include <signal.h>
#include <errno.h>


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


static listen_queue_t listen1;
static listen_queue_t listen2;
listen_queue_t *listen = &listen1;

volatile sig_atomic_t alive = 1;

int async(int fd, int events, int flags, void (*cb)(void *), void *arg, void (*err_cb)(void *), void *err_arg) {
    return -1;
}

void async_thread(void) {

    int num_fds = 0;
    struct pollfd fds[256];

    // main event loop
    while (alive) {
        // swap listen queue
        listen_queue_t *l = listen;
        listen = (listen == &listen1) ? &listen2 : &listen1;

        // fill fds with newly added
        for (int i = 0; i < l->n; i++, num_fds++) {
            fds[num_fds].fd = l->q[i].fd;
            fds[num_fds].events = l->q[i].events;
        }

        int ready_fds = poll(fds, num_fds, -1);
        if (ready_fds < 0) {
            if (errno == EINTR) {
                // interrupt
                continue;
            } else {
                // other error
                critical("Unable to poll for events");
                return;
            }
        }

        for (int i = 0; i < num_fds; i++) {
            // TODO
        }
    }
}
