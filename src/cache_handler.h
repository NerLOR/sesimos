/**
 * sesimos - secure, simple, modern web server
 * @brief File cache implementation (header file)
 * @file src/cache_handler.h
 * @author Lorenz Stechauner
 * @date 2020-12-19
 */

#ifndef SESIMOS_CACHE_HANDLER_H
#define SESIMOS_CACHE_HANDLER_H

#include "lib/uri.h"

#define CACHE_ENTRIES 1024

#define CACHE_DIRTY 1

#ifndef CACHE_MAGIC_FILE
#   define CACHE_MAGIC_FILE "/usr/share/file/misc/magic.mgc"
#endif


typedef struct {
    char filename[256];
    unsigned char webroot_len;
    unsigned char flags;
    metadata_t meta;
} cache_entry_t;

typedef struct {
    char sig[6];
    unsigned char ver;
    cache_entry_t entries[CACHE_ENTRIES];
} cache_t;

int cache_init(void);

void cache_stop(void);

int cache_join(void);

void cache_mark_dirty(cache_t *cache, const char *filename);

void cache_init_uri(cache_t *cache, http_uri *uri);

#endif //SESIMOS_CACHE_HANDLER_H
