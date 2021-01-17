/**
 * Necronda Web Server
 * File cache implementation (header file)
 * src/cache.h
 * Lorenz Stechauner, 2020-12-19
 */

#ifndef NECRONDA_SERVER_CACHE_H
#define NECRONDA_SERVER_CACHE_H

#include "uri.h"

#include <stdio.h>
#include <zlib.h>
#include <magic.h>
#include <sys/ipc.h>
#include <sys/shm.h>


magic_t magic;

typedef struct {
    char filename[256];
    unsigned char webroot_len;
    unsigned char is_updating:1;
    meta_data meta;
} cache_entry;

cache_entry *cache;

int cache_continue = 1;

int magic_init();

void cache_process_term();

int cache_process();

int cache_init();

int cache_unload();

int cache_update_entry(int entry_num, const char *filename, const char *webroot);

int cache_filename_comp_invalid(const char *filename);

int uri_cache_init(http_uri *uri);

#endif //NECRONDA_SERVER_CACHE_H
