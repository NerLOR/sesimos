/**
 * Necronda Web Server
 * File cache implementation (header file)
 * src/cache.h
 * Lorenz Stechauner, 2020-12-19
 */

#ifndef NECRONDA_SERVER_CACHE_H
#define NECRONDA_SERVER_CACHE_H

#include <magic.h>

magic_t magic;

typedef struct {
    char *etag;
    char *type;
    char *subtype;
    char *filename_comp;
    struct stat stat;
} meta_data;

typedef struct {
    char *filename;
    unsigned short filename_len;
    meta_data meta;
} cache_entry;

cache_entry cache[FILE_CACHE_SIZE];
int cache_entries = 0;

#endif //NECRONDA_SERVER_CACHE_H
