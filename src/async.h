

#ifndef SESIMOS_ASYNC_H
#define SESIMOS_ASYNC_H

#define async_read(fd, cb, arg, err_cb, err_arg) async(fd, 0, 0, cb, arg, err, err_arg)
#define async_read_keep(fd, cb, arg, err_cb, err_arg) async(fd, 0, 0, cb, arg, err, err_arg)

int async(int fd, int events, int flags, void (*cb)(void *), void *arg, void (*err_cb)(void *), void *err_arg);

void async_thread(void);

#endif //SESIMOS_ASYNC_H
