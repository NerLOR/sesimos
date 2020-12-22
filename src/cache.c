/**
 * Necronda Web Server
 * File cache implementation
 * src/cache.c
 * Lorenz Stechauner, 2020-12-19
 */

#include "cache.h"
#include "uri.h"

int magic_init() {
    magic = magic_open(MAGIC_MIME);
    if (magic == NULL) {
        fprintf(stderr, ERR_STR "Unable to open magic cookie: %s" CLR_STR "\n", strerror(errno));
        return -1;
    }
    if (magic_load(magic, MAGIC_FILE) != 0) {
        fprintf(stderr, ERR_STR "Unable to load magic cookie: %s" CLR_STR "\n", magic_error(magic));
        return -2;
    }
    return 0;
}

int cache_init() {
    if (magic_init() != 0) {
        return -1;
    }

    int shm_id = shmget(SHM_KEY, FILE_CACHE_SIZE * sizeof(cache_entry), IPC_CREAT | IPC_EXCL);
    if (shm_id < 0) {
        fprintf(stderr, ERR_STR "Unable to create shared memory: %s" CLR_STR "\n", strerror(errno));
        return -2;
    }

    void *shm = shmat(shm_id, NULL, SHM_RDONLY);
    if (shm == (void *) -1) {
        fprintf(stderr, ERR_STR "Unable to attach shared memory (ro): %s" CLR_STR "\n", strerror(errno));
        return -3;
    }
    cache = shm;

    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        fprintf(stderr, ERR_STR "Unable to attach shared memory (rw): %s" CLR_STR "\n", strerror(errno));
        return -4;
    }
    cache = shm_rw;
    memset(cache, 0, FILE_CACHE_SIZE * sizeof(cache_entry));
    // TODO load cache from file
    shmdt(shm_rw);
    cache = shm;

    return 0;
}

int cache_unload() {
    int shm_id = shmget(SHM_KEY, 0, 0);
    if (shm_id < 0) {
        fprintf(stderr, ERR_STR "Unable to create shared memory: %s" CLR_STR "\n", strerror(errno));
    } else if (shmctl(shm_id, IPC_RMID, NULL) < 0) {
        fprintf(stderr, ERR_STR "Unable to configure shared memory: %s" CLR_STR "\n", strerror(errno));
    }
    shmdt(cache);
    return 0;
}

int cache_update_entry(int entry_num, const char *filename) {
    void *cache_ro = cache;
    int shm_id = shmget(SHM_KEY, 0, 0);
    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        print(ERR_STR "Unable to attach shared memory (rw): %s" CLR_STR, strerror(errno));
        return -1;
    }
    cache = shm_rw;

    struct stat statbuf;
    stat(filename, &statbuf);
    memcpy(&cache[entry_num].meta.stat, &statbuf, sizeof(statbuf));

    strcpy(cache[entry_num].filename, filename);
    magic_setflags(magic, MAGIC_MIME_TYPE);
    strcpy(cache[entry_num].meta.type, magic_file(magic, filename));
    magic_setflags(magic, MAGIC_MIME_ENCODING);
    strcpy(cache[entry_num].meta.charset, magic_file(magic, filename));
    cache[entry_num].is_valid_etag = 0;
    cache[entry_num].is_updating = 0;

    shmdt(shm_rw);
    cache = cache_ro;
    return 0;
}

int uri_cache_init(http_uri *uri) {
    if (uri->filename == NULL) {
        return 0;
    }

    int i;
    for (i = 0; i < FILE_CACHE_SIZE; i++) {
        if (cache[i].filename[0] != 0 && strncmp(cache[i].filename, uri->filename, cache[i].filename_len) == 0) {
            uri->meta = &cache[i].meta;
            if (cache[i].is_updating) {
                return 0;
            } else {
                break;
            }
        }
    }

    if (uri->meta == NULL) {
        for (i = 0; i < FILE_CACHE_SIZE; i++) {
            if (cache[i].filename[0] == 0) {
                if (cache_update_entry(i, uri->filename) != 0) {
                    return -1;
                }
                uri->meta = &cache[i].meta;
                break;
            }
        }
    } else {
        struct stat statbuf;
        stat(uri->filename, &statbuf);
        if (memcmp(&uri->meta->stat.st_mtime, &statbuf.st_mtime, sizeof(statbuf.st_mtime)) != 0) {
            if (cache_update_entry(i, uri->filename) != 0) {
                return -1;
            }
        }
    }

    return 0;
}
