/**
 * sesimos - secure, simple, modern web server
 * File cache implementation (header file)
 * src/lib/cache.h
 * Lorenz Stechauner, 2020-12-19
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

int magic_init();

void cache_process_term();

int cache_process();

int cache_init();

int cache_unload();

int cache_update_entry(int entry_num, const char *filename, const char *webroot);

int cache_filename_comp_invalid(const char *filename);

int uri_cache_init(http_uri *uri);

#endif //SESIMOS_CACHE_H
