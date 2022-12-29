
#include "mpmc.h"
#include "../logger.h"

#include <errno.h>
#include <malloc.h>
#include <memory.h>
#include <pthread.h>
#include <signal.h>

typedef struct {
    mpmc_t *ctx;
    int worker_id;
} mpmc_arg_t;

static void *mpmc_worker(void *arg);

int mpmc_init(mpmc_t *ctx, int n_workers, int buf_size, void (*consumer)(void *obj), const char *name) {
    ctx->alive = 1;
    ctx->n_workers = n_workers;
    ctx->size = buf_size, ctx->max_size = buf_size;
    ctx->rd = 0, ctx->wr = 0;
    ctx->buffer = NULL, ctx->workers = NULL;
    ctx->consumer = consumer;
    ctx->name = name;

    if (sem_init(&ctx->free, 0, ctx->size) != 0 ||
        sem_init(&ctx->used, 0, 0)         != 0 ||
        sem_init(&ctx->lck_rd, 0, 1)       != 0 ||
        sem_init(&ctx->lck_wr, 0, 1)       != 0)
    {
        mpmc_destroy(ctx);
        return -1;
    }

    if ((ctx->buffer  = malloc(ctx->size      * sizeof(void *)))    == NULL ||
        (ctx->workers = malloc(ctx->n_workers * sizeof(pthread_t))) == NULL)
    {
        mpmc_destroy(ctx);
        return -1;
    }

    memset(ctx->buffer,  0, ctx->size      * sizeof(void *));
    memset(ctx->workers, 0, ctx->n_workers * sizeof(pthread_t));

    for (int i = 0; i < ctx->n_workers; i++) {
        int ret;
        if ((ret = pthread_create(&ctx->workers[i], NULL, mpmc_worker, ctx)) != 0) {
            mpmc_destroy(ctx);
            errno = ret;
            return -1;
        }
    }

    return 0;
}

int mpmc_queue(mpmc_t *ctx, void *obj) {
    // wait for buffer to be emptied
    try_again_1:
    if (sem_wait(&ctx->free) != 0) {
        if (errno == EINTR) {
            errno = 0;
            goto try_again_1;
        } else {
            return -1;
        }
    }

    // lock wr field
    try_again_2:
    if (sem_wait(&ctx->lck_wr) != 0) {
        if (errno == EINTR) {
            errno = 0;
            goto try_again_2;
        } else {
            sem_post(&ctx->free);
            return -1;
        }
    }

    int p = ctx->wr;
    ctx->wr = (ctx->wr + 1) % ctx->size;

    // unlock wr field
    sem_post(&ctx->lck_wr);

    // fill buffer with object
    ctx->buffer[p] = obj;

    // inform worker
    sem_post(&ctx->used);

    return 0;
}

static void *mpmc_worker(void *arg) {
    mpmc_t *ctx = arg;

    int id;
    for (id = 0; id < ctx->n_workers && ctx->workers[id] != pthread_self(); id++);
    logger_set_name("%s/%i", ctx->name, id);

    while (ctx->alive) {
        // wait for buffer to be filled
        if (sem_wait(&ctx->used) != 0) {
            if (errno == EINTR) {
                errno = 0;
                continue;
            } else {
                critical("Unable to lock semaphore");
                errno = 0;
                break;
            }
        }

        // lock rd field
        if (sem_wait(&ctx->lck_rd) != 0) {
            if (errno == EINTR) {
                errno = 0;
                sem_post(&ctx->used);
                continue;
            } else {
                critical("Unable to lock semaphore");
                errno = 0;
                sem_post(&ctx->used);
                break;
            }
        }

        int p = ctx->rd;
        ctx->rd = (ctx->rd + 1) % ctx->size;

        // unlock rd field
        sem_post(&ctx->lck_rd);

        // consume object
        ctx->consumer(ctx->buffer[p]);
        logger_set_prefix("");

        // unlock slot in buffer
        sem_post(&ctx->free);
    }

    return NULL;
}

void mpmc_stop(mpmc_t *ctx) {
    ctx->alive = 0;
}

void mpmc_destroy(mpmc_t *ctx) {
    int e = errno;

    // stop threads, if running
    mpmc_stop(ctx);
    for (int i = 0; i < ctx->n_workers; i++) {
        if (ctx->workers[i] == 0) break;
        // FIXME
        pthread_kill(ctx->workers[i], SIGUSR1);
        //pthread_join(ctx->workers[i], NULL);
        pthread_cancel(ctx->workers[i]);
    }

    sem_destroy(&ctx->free);
    sem_destroy(&ctx->used);
    sem_destroy(&ctx->lck_rd);
    sem_destroy(&ctx->lck_wr);
    free(ctx->buffer);
    free(ctx->workers);

    // reset errno
    errno = e;
}

