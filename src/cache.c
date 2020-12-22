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

void cache_process_term() {
    cache_continue = 0;
}

int cache_process() {
    signal(SIGINT, cache_process_term);
    signal(SIGTERM, cache_process_term);

    int shm_id = shmget(SHM_KEY, FILE_CACHE_SIZE * sizeof(cache_entry), 0);
    if (shm_id < 0) {
        fprintf(stderr, ERR_STR "Unable to create shared memory: %s" CLR_STR "\n", strerror(errno));
        return -1;
    }
    shmdt(cache);
    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        fprintf(stderr, ERR_STR "Unable to attach shared memory (rw): %s" CLR_STR "\n", strerror(errno));
        return -2;
    }
    cache = shm_rw;

    mkdir("/var/necronda-server", 0655);

    FILE *cache_file = fopen("/var/necronda-server/cache", "rb");
    fread(cache, sizeof(cache_entry), FILE_CACHE_SIZE , cache_file);
    fclose(cache_file);

    for (int i = 0; i < FILE_CACHE_SIZE; i++) {
        cache[i].is_updating = 0;
    }

    FILE *file;
    char buf[16384];
    unsigned long read;
    int compress;
    SHA_CTX ctx;
    unsigned char hash[SHA_DIGEST_LENGTH];
    while (cache_continue) {
        for (int i = 0; i < FILE_CACHE_SIZE; i++) {
            if (cache[i].filename[0] != 0 && cache[i].meta.etag[0] == 0 && !cache[i].is_updating) {
                cache[i].is_updating = 1;
                SHA1_Init(&ctx);
                file = fopen(cache[i].filename, "rb");
                compress = strncmp(cache[i].meta.type, "text/", 5) == 0;
                while ((read = fread(buf, 1, sizeof(buf), file)) > 0) {
                    SHA1_Update(&ctx, buf, read);
                    if (compress) {
                        // TODO compress text/* files
                    }
                }
                SHA1_Final(hash, &ctx);
                memset(cache[i].meta.etag, 0, sizeof(cache[i].meta.etag));
                for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
                    sprintf(cache[i].meta.etag + j * 2, "%02x", hash[j]);
                }
                fclose(file);
                cache[i].is_updating = 0;
            }
        }

        cache_file = fopen("/var/necronda-server/cache", "wb");
        fwrite(cache, sizeof(cache_entry), FILE_CACHE_SIZE , cache_file);
        fclose(cache_file);
        sleep(1);
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
    shmdt(shm_rw);
    cache = shm;

    pid_t pid = fork();
    if (pid == 0) {
        // child
        if (cache_process() == 0) {
            return 1;
        } else {
            return -6;
        }
    } else if (pid > 0) {
        // parent
        fprintf(stderr, "Started child process with PID %i as cache-updater\n", pid);
        children[0] = pid;
    } else {
        fprintf(stderr, ERR_STR "Unable to create child process: %s" CLR_STR "\n", strerror(errno));
        return -5;
    }

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
    const char *type = magic_file(magic, filename);
    char type_new[24];
    sprintf(type_new, "%s", type);
    if (strncmp(type, "text/plain", 10) == 0) {
        if (strncmp(filename + strlen(filename) - 4, ".css", 4) == 0) {
            sprintf(type_new, "text/css");
        } else if (strncmp(filename + strlen(filename) - 3, ".js", 3) == 0) {
            sprintf(type_new, "text/javascript");
        }
    }
    strcpy(cache[entry_num].meta.type, type_new);
    magic_setflags(magic, MAGIC_MIME_ENCODING);
    strcpy(cache[entry_num].meta.charset, magic_file(magic, filename));
    memset(cache[entry_num].meta.etag, 0, sizeof(cache[entry_num].meta.etag));
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
        if (cache[i].filename[0] != 0 && strlen(cache[i].filename) == strlen(uri->filename) &&
            strcmp(cache[i].filename, uri->filename) == 0) {
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
