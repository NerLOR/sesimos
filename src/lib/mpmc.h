
#ifndef SESIMOS_MPMC_H
#define SESIMOS_MPMC_H

#include <semaphore.h>

typedef struct {
    volatile unsigned int alive:1;
    int n_workers;
    volatile int rd, wr;
    sem_t free, used, lck_rd, lck_wr;
    int size, max_size;
    void *volatile *buffer;
    pthread_t *workers;
    void (*consumer)(void *obj);
    const char* name;
} mpmc_t;

int mpmc_init(mpmc_t *ctx, int n_workers, int buf_size, void (*consumer)(void *), const char *name);

int mpmc_queue(mpmc_t *ctx, void *obj);

void mpmc_stop(mpmc_t *ctx);

void mpmc_destroy(mpmc_t *ctx);

#endif //SESIMOS_MPMC_H
