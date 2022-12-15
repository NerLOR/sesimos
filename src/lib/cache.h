/**
 * sesimos - secure, simple, modern web server
 * @brief File cache implementation (header file)
 * @file src/lib/cache.h
 * @author Lorenz Stechauner
 * @date 2020-12-19
 */

#ifndef SESIMOS_CACHE_H
#define SESIMOS_CACHE_H

#include "uri.h"

#define CACHE_SHM_KEY 255641
#define CACHE_ENTRIES 1024
#define CACHE_BUF_SIZE 16384

#ifndef CACHE_MAGIC_FILE
#   define CACHE_MAGIC_FILE "/usr/share/file/misc/magic.mgc"
#endif


typedef struct {
    char filename[256];
    unsigned char webroot_len;
    unsigned char is_updating:1;
    meta_data meta;
} cache_entry;

extern cache_entry *cache;

extern int cache_continue;

void cache_process_term(int _);

int cache_process(void);

int cache_init(void);

int cache_unload(void);

int cache_filename_comp_invalid(const char *filename);

int cache_init_uri(http_uri *uri);

#endif //SESIMOS_CACHE_H
