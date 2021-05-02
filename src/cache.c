/**
 * Necronda Web Server
 * File cache implementation
 * src/cache.c
 * Lorenz Stechauner, 2020-12-19
 */

#include "cache.h"


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

    int shm_id = shmget(SHM_KEY_CACHE, FILE_CACHE_SIZE * sizeof(cache_entry), 0);
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

    if (mkdir("/var/necronda-server/", 0755) < 0) {
        if (errno != EEXIST) {
            fprintf(stderr, ERR_STR "Unable to create directory '/var/necronda-server/': %s" CLR_STR "\n", strerror(errno));
            return -3;
        }
    }

    FILE *cache_file = fopen("/var/necronda-server/cache", "rb");
    if (cache_file != NULL) {
        fread(cache, sizeof(cache_entry), FILE_CACHE_SIZE, cache_file);
        fclose(cache_file);
    }

    for (int i = 0; i < FILE_CACHE_SIZE; i++) {
        cache[i].is_updating = 0;
    }

    FILE *file;
    char buf[16384];
    char comp_buf[16384];
    char filename_comp[256];
    unsigned long read;
    int compress;
    SHA_CTX ctx;
    unsigned char hash[SHA_DIGEST_LENGTH];
    int cache_changed = 0;
    int p_len;
    while (cache_continue) {
        for (int i = 0; i < FILE_CACHE_SIZE; i++) {
            if (cache[i].filename[0] != 0 && cache[i].meta.etag[0] == 0 && !cache[i].is_updating) {
                cache[i].is_updating = 1;
                fprintf(stdout, "[cache] Hashing file %s\n", cache[i].filename);
                SHA1_Init(&ctx);
                file = fopen(cache[i].filename, "rb");
                compress = mime_is_compressible(cache[i].meta.type);

                int level = NECRONDA_ZLIB_LEVEL;
                z_stream strm;
                FILE *comp_file = NULL;
                if (compress) {
                    sprintf(buf, "%.*s/.necronda-server", cache[i].webroot_len, cache[i].filename);
                    mkdir(buf, 0755);
                    sprintf(buf, "%.*s/.necronda-server/cache", cache[i].webroot_len, cache[i].filename);
                    mkdir(buf, 0700);
                    char *rel_path = cache[i].filename + cache[i].webroot_len + 1;
                    for (int j = 0; j < strlen(rel_path); j++) {
                        char ch = rel_path[j];
                        if (ch == '/') {
                            ch = '_';
                        }
                        buf[j] = ch;
                    }
                    buf[strlen(rel_path)] = 0;
                    p_len = snprintf(filename_comp, sizeof(filename_comp), "%.*s/.necronda-server/cache/%s.z",
                                     cache[i].webroot_len, cache[i].filename, buf);
                    if (p_len < 0 || p_len >= sizeof(filename_comp)) {
                        fprintf(stderr, ERR_STR "Unable to open cached file: "
                                                "File name for compressed file too long" CLR_STR "\n");
                        goto comp_err;
                    }
                    fprintf(stdout, "[cache] Compressing file %s\n", cache[i].filename);
                    comp_file = fopen(filename_comp, "wb");
                    if (comp_file == NULL) {
                        fprintf(stderr, ERR_STR "Unable to open cached file: %s" CLR_STR "\n", strerror(errno));
                        comp_err:
                        compress = 0;
                    } else {
                        strm.zalloc = Z_NULL;
                        strm.zfree = Z_NULL;
                        strm.opaque = Z_NULL;
                        if (deflateInit(&strm, level) != Z_OK) {
                            fprintf(stderr, ERR_STR "Unable to init deflate: %s" CLR_STR "\n", strerror(errno));
                            compress = 0;
                            fclose(comp_file);
                        }
                    }
                }

                while ((read = fread(buf, 1, sizeof(buf), file)) > 0) {
                    SHA1_Update(&ctx, buf, read);
                    if (compress) {
                        strm.avail_in = read;
                        strm.next_in = (unsigned char *) buf;
                        do {
                            strm.avail_out = sizeof(comp_buf);
                            strm.next_out = (unsigned char *) comp_buf;
                            deflate(&strm, feof(file) ? Z_FINISH : Z_NO_FLUSH);
                            fwrite(comp_buf, 1, sizeof(comp_buf) - strm.avail_out, comp_file);
                            strm.avail_in = 0;
                        } while (strm.avail_out == 0);
                    }
                }

                if (compress) {
                    deflateEnd(&strm);
                    fclose(comp_file);
                    fprintf(stdout, "[cache] Finished compressing file %s\n", cache[i].filename);
                    strcpy(cache[i].meta.filename_comp, filename_comp);
                } else {
                    memset(cache[i].meta.filename_comp, 0, sizeof(cache[i].meta.filename_comp));
                }
                SHA1_Final(hash, &ctx);
                memset(cache[i].meta.etag, 0, sizeof(cache[i].meta.etag));
                for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
                    sprintf(cache[i].meta.etag + j * 2, "%02x", hash[j]);
                }
                fclose(file);
                fprintf(stdout, "[cache] Finished hashing file %s\n", cache[i].filename);
                cache[i].is_updating = 0;
                cache_changed = 1;
            }
        }

        if (cache_changed) {
            cache_changed = 0;
            cache_file = fopen("/var/necronda-server/cache", "wb");
            fwrite(cache, sizeof(cache_entry), FILE_CACHE_SIZE, cache_file);
            fclose(cache_file);
        } else {
            sleep(1);
        }
    }
    return 0;
}

int cache_init() {
    if (magic_init() != 0) {
        return -1;
    }

    int shm_id = shmget(SHM_KEY_CACHE, FILE_CACHE_SIZE * sizeof(cache_entry), IPC_CREAT | IPC_EXCL | 0600);
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
    int shm_id = shmget(SHM_KEY_CACHE, 0, 0);
    if (shm_id < 0) {
        fprintf(stderr, ERR_STR "Unable to get shared memory id: %s" CLR_STR "\n", strerror(errno));
        shmdt(cache);
        return -1;
    } else if (shmctl(shm_id, IPC_RMID, NULL) < 0) {
        fprintf(stderr, ERR_STR "Unable to configure shared memory: %s" CLR_STR "\n", strerror(errno));
        shmdt(cache);
        return -1;
    }
    shmdt(cache);
    return 0;
}

int cache_update_entry(int entry_num, const char *filename, const char *webroot) {
    void *cache_ro = cache;
    int shm_id = shmget(SHM_KEY_CACHE, 0, 0);
    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        print(ERR_STR "Unable to attach shared memory (rw): %s" CLR_STR, strerror(errno));
        return -1;
    }
    cache = shm_rw;

    struct stat statbuf;
    stat(filename, &statbuf);
    memcpy(&cache[entry_num].meta.stat, &statbuf, sizeof(statbuf));

    cache[entry_num].webroot_len = (unsigned char) strlen(webroot);
    strcpy(cache[entry_num].filename, filename);

    magic_setflags(magic, MAGIC_MIME_TYPE);
    const char *type = magic_file(magic, filename);
    char type_new[24];
    sprintf(type_new, "%s", type);
    if (strcmp(type, "text/plain") == 0) {
        if (strcmp(filename + strlen(filename) - 4, ".css") == 0) {
            sprintf(type_new, "text/css");
        } else if (strcmp(filename + strlen(filename) - 3, ".js") == 0) {
            sprintf(type_new, "text/javascript");
        }
    }
    strcpy(cache[entry_num].meta.type, type_new);

    magic_setflags(magic, MAGIC_MIME_ENCODING);
    strcpy(cache[entry_num].meta.charset, magic_file(magic, filename));

    memset(cache[entry_num].meta.etag, 0, sizeof(cache[entry_num].meta.etag));
    memset(cache[entry_num].meta.filename_comp, 0, sizeof(cache[entry_num].meta.filename_comp));
    cache[entry_num].is_updating = 0;

    shmdt(shm_rw);
    cache = cache_ro;
    return 0;
}

int cache_filename_comp_invalid(const char *filename) {
    void *cache_ro = cache;
    int shm_id = shmget(SHM_KEY_CACHE, 0, 0);
    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        print(ERR_STR "Unable to attach shared memory (rw): %s" CLR_STR, strerror(errno));
        return -1;
    }
    cache = shm_rw;

    int i;
    for (i = 0; i < FILE_CACHE_SIZE; i++) {
        if (cache[i].filename[0] != 0 && strlen(cache[i].filename) == strlen(filename) &&
                strcmp(cache[i].filename, filename) == 0) {
            if (cache[i].is_updating) {
                return 0;
            } else {
                break;
            }
        }
    }

    memset(cache[i].meta.etag, 0, sizeof(cache[i].meta.etag));
    memset(cache[i].meta.filename_comp, 0, sizeof(cache[i].meta.filename_comp));
    cache[i].is_updating = 0;

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
                if (cache_update_entry(i, uri->filename, uri->webroot) != 0) {
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
            if (cache_update_entry(i, uri->filename, uri->webroot) != 0) {
                return -1;
            }
        }
    }

    return 0;
}
