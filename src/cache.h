/**
 * Necronda Web Server
 * File cache implementation (header file)
 * src/cache.h
 * Lorenz Stechauner, 2020-12-19
 */

#ifndef NECRONDA_SERVER_CACHE_H
#define NECRONDA_SERVER_CACHE_H

#include <magic.h>
#include <sys/ipc.h>
#include <sys/shm.h>

magic_t magic;

typedef struct {
    char etag[64];
    char type[24];
    char charset[16];
    char filename_comp[256];
    struct stat stat;
} meta_data;

typedef struct {
    char filename[256];
    unsigned short filename_len;
    unsigned char is_valid_etag:1;
    unsigned char is_updating:1;
    meta_data meta;
} cache_entry;

cache_entry *cache;

#endif //NECRONDA_SERVER_CACHE_H
