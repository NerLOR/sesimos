/**
 * Necronda Web Server
 * File cache implementation (header file)
 * src/lib/cache.h
 * Lorenz Stechauner, 2020-12-19
 */

#ifndef NECRONDA_SERVER_CACHE_H
#define NECRONDA_SERVER_CACHE_H

#include "uri.h"

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

#endif //NECRONDA_SERVER_CACHE_H
