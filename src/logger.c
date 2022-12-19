/**
 * sesimos - secure, simple, modern web server
 * @brief Logger
 * @file src/logger.h
 * @author Lorenz Stechauner
 * @date 2022-12-10
 */

#include "logger.h"
#include "lib/utils.h"

#include <stdio.h>
#include <pthread.h>
#include <semaphore.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <malloc.h>

#define LOG_MAX_MSG_SIZE 2048
#define LOG_BUF_SIZE 16
#define LOG_NAME_LEN 12
#define LOG_PREFIX_LEN 256

#define LOG_PREFIX "[%-8s][%-6s]"

typedef struct {
    log_lvl_t lvl;
    char name[LOG_NAME_LEN];
    char prefix[LOG_PREFIX_LEN];
    char txt[LOG_MAX_MSG_SIZE];
} log_msg_t;

typedef struct {
    int rd;
    int wr;
    log_msg_t msgs[LOG_BUF_SIZE];
} buf_t;

static pthread_t thread;
static volatile sig_atomic_t logger_alive = 0;
static sem_t sem_buf, sem_buf_free, sem_buf_used;
static buf_t buffer;

static pthread_key_t key_name = -1, key_prefix = -1;
static char global_name[LOG_NAME_LEN] = "", global_prefix[LOG_PREFIX_LEN] = "";

static const char *level_keywords[] = {
        "EMERG",
        "ALERT",
        "CRIT",
        "ERROR",
        "WARN",
        "NOTICE",
        "INFO",
        "DEBUG"
};

static void err(const char *restrict msg) {
    char err_buf[64];
    strerror_r(errno, err_buf, sizeof(err_buf));
    fprintf(stderr, ERR_STR LOG_PREFIX " %s: %s" CLR_STR "\n", "logger", level_keywords[LOG_CRITICAL], msg, err_buf);
}

void logmsgf(log_lvl_t level, const char *restrict format, ...) {
    char buf[256];
    char err_buf[64];
    va_list args;
    va_start(args, format);

    const char *color = (level <= LOG_ERROR) ? ERR_STR : ((level <= LOG_WARNING) ? WRN_STR : "");
    if (errno != 0) {
        strerror_r(errno, err_buf, sizeof(err_buf));
        snprintf(buf, sizeof(buf), "%s%s: %s" CLR_STR, color, format, err_buf);
    } else {
        snprintf(buf, sizeof(buf), "%s%s" CLR_STR, color, format);
    }

    void *name = pthread_getspecific(key_name);
    if (name == NULL && global_name[0] != 0) name = global_name;
    void *prefix = pthread_getspecific(key_prefix);
    if (prefix == NULL && global_prefix[0] != 0) prefix = global_prefix;

    if (!logger_alive) {
        // no logger thread running
        // simply write to stdout without synchronization
        printf("%s" LOG_PREFIX "%s%s ", color, (name != NULL) ? (char *) name : "", level_keywords[level], CLR_STR, (prefix != NULL) ? (char *) prefix : "");
        vprintf(buf, args);
        printf("\n");
    } else {
        // wait for free slot in buffer
        try_again_free:
        if (sem_wait(&sem_buf_free) != 0) {
            if (errno == EINTR) {
                goto try_again_free;
            } else {
                err("Unable to lock semaphore");
            }
            // cleanup
            va_end(args);
            return;
        }

        // try to lock buffer
        try_again_buf:
        if (sem_wait(&sem_buf) != 0) {
            if (errno == EINTR) {
                goto try_again_buf;
            } else {
                err("Unable to lock semaphore");
            }
            // cleanup
            sem_post(&sem_buf_free);
            va_end(args);
            return;
        }

        // write message to buffer
        log_msg_t *msg = &buffer.msgs[buffer.rd];
        buffer.rd = (buffer.rd + 1) % LOG_BUF_SIZE;

        vsnprintf(msg->txt, sizeof(msg->txt), buf, args);
        msg->lvl = level;

        if (name != NULL) {
            snprintf(msg->name, sizeof(msg->name), "%s", (char *) name);
        } else {
            msg->name[0] = 0;
        }

        if (prefix != NULL) {
            snprintf(msg->prefix, sizeof(msg->prefix), "%s", (char *) prefix);
        } else {
            msg->prefix[0] = 0;
        }

        // unlock buffer
        sem_post(&sem_buf);

        // unlock slot in buffer for logger
        sem_post(&sem_buf_used);
    }

    // cleanup
    va_end(args);
}

static void logger_destroy(void) {
    sem_destroy(&sem_buf);
    sem_destroy(&sem_buf_free);
    sem_destroy(&sem_buf_used);
}

static int logger_remaining(void) {
    int val = 0;
    sem_getvalue(&sem_buf_used, &val);
    return val;
}

void logger_set_name(const char *restrict name) {
    if (key_name == -1) {
        // not initialized
        strncpy(global_name, name, sizeof(global_name));
    } else {
        int ret;
        void *ptr = pthread_getspecific(key_name);
        if (!ptr) {
            ptr = malloc(LOG_NAME_LEN);
            if ((ret = pthread_setspecific(key_name, ptr)) != 0) {
                errno = ret;
                err("Unable to set thread specific values");
                return;
            }
        }
        strncpy(ptr, name, LOG_NAME_LEN);
    }
}

void logger_set_prefix(const char *restrict prefix) {
    if (key_prefix == -1) {
        // not initialized
        strncpy(global_prefix, prefix, sizeof(global_prefix));
    } else {
        int ret;
        void *ptr = pthread_getspecific(key_prefix);
        if (!ptr) {
            ptr = malloc(LOG_PREFIX_LEN);
            if ((ret = pthread_setspecific(key_prefix, ptr)) != 0) {
                errno = ret;
                err("Unable to set thread specific values");
                return;
            }
        }
        strncpy(ptr, prefix, LOG_PREFIX_LEN);
    }
}

static void *logger_thread(void *arg) {
    logger_set_name("logger");
    logger_alive = 1;

    while (logger_alive || logger_remaining() > 0) {
        // wait for buffer to be filled
        if (sem_wait(&sem_buf_used) != 0) {
            if (errno == EINTR) {
                continue;
            } else {
                err("Unable to lock semaphore");
                break;
            }
        }

        log_msg_t *msg = &buffer.msgs[buffer.wr];
        buffer.wr = (buffer.wr + 1) % LOG_BUF_SIZE;

        printf("%s" LOG_PREFIX "%s%s %s\n",
               (msg->lvl <= LOG_ERROR) ? ERR_STR : ((msg->lvl <= LOG_WARNING) ? WRN_STR : ""),
               (msg->name[0] != 0) ? (char *) msg->name : "", level_keywords[msg->lvl], CLR_STR,
               (msg->prefix[0] != 0) ? (char *) msg->prefix : "",  msg->txt);

        // unlock slot in buffer
        sem_post(&sem_buf_free);
    }

    logger_destroy();

    return NULL;
}

int logger_init(void) {
    int ret;

    // try to initialize all three semaphores
    if (sem_init(&sem_buf, 0, 1) != 0 || sem_init(&sem_buf_free, 0, LOG_BUF_SIZE) != 0 || sem_init(&sem_buf_used, 0, 0) != 0) {
        err("Unable to initialize semaphore");
        logger_destroy();
        return -1;
    }

    // initialize read/write heads
    buffer.rd = 0;
    buffer.wr = 0;

    // initialize thread specific values (keys)
    if ((ret = pthread_key_create(&key_name, free)) != 0 || (ret = pthread_key_create(&key_prefix, free)) != 0) {
        errno = ret;
        err("Unable to initialize thread specific values");
        logger_destroy();
        return -1;
    }

    pthread_create(&thread, NULL, logger_thread, NULL);

    return 0;
}

void logger_stop(void) {
    logger_alive = 0;
}
