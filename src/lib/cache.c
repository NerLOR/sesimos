/**
 * sesimos - secure, simple, modern web server
 * @brief File cache implementation
 * @file src/lib/cache.c
 * @author Lorenz Stechauner
 * @date 2020-12-19
 */

#include "../logger.h"
#include "cache.h"
#include "utils.h"
#include "compress.h"

#include <stdio.h>
#include <magic.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <openssl/evp.h>


int cache_continue = 1;
magic_t magic;
cache_entry *cache;

int magic_init(void) {
    magic = magic_open(MAGIC_MIME);
    if (magic == NULL) {
        critical("Unable to open magic cookie");
        return -1;
    }
    if (magic_load(magic, CACHE_MAGIC_FILE) != 0) {
        critical("Unable to load magic cookie: %s", magic_error(magic));
        return -2;
    }
    return 0;
}

void cache_process_term(int _) {
    cache_continue = 0;
}

int cache_process(void) {
    errno = 0;
    signal(SIGINT, cache_process_term);
    signal(SIGTERM, cache_process_term);

    logger_set_name("cache");

    int shm_id = shmget(CACHE_SHM_KEY, CACHE_ENTRIES * sizeof(cache_entry), 0);
    if (shm_id < 0) {
        critical("Unable to create cache shared memory");
        return -1;
    }

    shmdt(cache);
    errno = 0;
    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        critical("Unable to attach cache shared memory (rw)");
        return -2;
    }
    cache = shm_rw;

    if (mkdir("/var/sesimos/", 0755) < 0 && errno != EEXIST) {
        critical("Unable to create directory '/var/sesimos/'");
        return -3;
    }

    if (mkdir("/var/sesimos/server/", 0755) < 0 && errno != EEXIST) {
        critical("Unable to create directory '/var/sesimos/server/'");
        return -3;
    }

    FILE *cache_file = fopen("/var/sesimos/server/cache", "rb");
    if (cache_file != NULL) {
        fread(cache, sizeof(cache_entry), CACHE_ENTRIES, cache_file);
        fclose(cache_file);
    }

    errno = 0;

    for (int i = 0; i < CACHE_ENTRIES; i++) {
        cache[i].is_updating = 0;
    }

    FILE *file;
    char buf[CACHE_BUF_SIZE], comp_buf[CACHE_BUF_SIZE], filename_comp_gz[256], filename_comp_br[256];
    unsigned long read;
    int compress;
    EVP_MD_CTX *ctx;
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    int cache_changed = 0;
    int p_len_gz, p_len_br;
    int ret;
    while (cache_continue) {
        for (int i = 0; i < CACHE_ENTRIES; i++) {
            if (cache[i].filename[0] != 0 && cache[i].meta.etag[0] == 0 && !cache[i].is_updating) {
                cache[i].is_updating = 1;
                info("Hashing file %s", cache[i].filename);

                ctx = EVP_MD_CTX_new();
                EVP_DigestInit(ctx, EVP_sha1());
                file = fopen(cache[i].filename, "rb");
                compress = mime_is_compressible(cache[i].meta.type);

                compress_ctx comp_ctx;
                FILE *comp_file_gz = NULL;
                FILE *comp_file_br = NULL;
                if (compress) {
                    sprintf(buf, "%.*s/.sesimos", cache[i].webroot_len, cache[i].filename);
                    if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
                        error("Unable to create directory %s", buf);
                        goto comp_err;
                    }

                    sprintf(buf, "%.*s/.sesimos/cache", cache[i].webroot_len, cache[i].filename);
                    if (mkdir(buf, 0700) != 0 && errno != EEXIST) {
                        error("Unable to create directory %s", buf);
                        goto comp_err;
                    }
                    errno = 0;

                    char *rel_path = cache[i].filename + cache[i].webroot_len + 1;
                    for (int j = 0; j < strlen(rel_path); j++) {
                        char ch = rel_path[j];
                        if (ch == '/') ch = '_';
                        buf[j] = ch;
                    }
                    buf[strlen(rel_path)] = 0;

                    p_len_gz = snprintf(filename_comp_gz, sizeof(filename_comp_gz),
                                        "%.*s/.sesimos/cache/%s.gz",
                                        cache[i].webroot_len, cache[i].filename, buf);
                    p_len_br = snprintf(filename_comp_br, sizeof(filename_comp_br),
                                        "%.*s/.sesimos/cache/%s.br",
                                        cache[i].webroot_len, cache[i].filename, buf);
                    if (p_len_gz < 0 || p_len_gz >= sizeof(filename_comp_gz) || p_len_br < 0 || p_len_br >= sizeof(filename_comp_br)) {
                        error("Unable to open cached file: File name for compressed file too long");
                        goto comp_err;
                    }

                    info("Compressing file %s", cache[i].filename);

                    comp_file_gz = fopen(filename_comp_gz, "wb");
                    comp_file_br = fopen(filename_comp_br, "wb");
                    if (comp_file_gz == NULL || comp_file_br == NULL) {
                        error("Unable to open cached file");
                        comp_err:
                        compress = 0;
                    } else {
                        ret = compress_init(&comp_ctx, COMPRESS_GZ | COMPRESS_BR);
                        if (ret != 0) {
                            error("Unable to init compression");
                            compress = 0;
                            fclose(comp_file_gz);
                            fclose(comp_file_br);
                        }
                    }
                }

                while ((read = fread(buf, 1, CACHE_BUF_SIZE, file)) > 0) {
                    EVP_DigestUpdate(ctx, buf, read);
                    if (compress) {
                        unsigned long avail_in, avail_out;
                        avail_in = read;
                        do {
                            avail_out = CACHE_BUF_SIZE;
                            compress_compress_mode(&comp_ctx, COMPRESS_GZ,buf + read - avail_in, &avail_in, comp_buf, &avail_out, feof(file));
                            fwrite(comp_buf, 1, CACHE_BUF_SIZE - avail_out, comp_file_gz);
                        } while (avail_in != 0 || avail_out != CACHE_BUF_SIZE);
                        avail_in = read;
                        do {
                            avail_out = CACHE_BUF_SIZE;
                            compress_compress_mode(&comp_ctx, COMPRESS_BR, buf + read - avail_in, &avail_in, comp_buf, &avail_out, feof(file));
                            fwrite(comp_buf, 1, CACHE_BUF_SIZE - avail_out, comp_file_br);
                        } while (avail_in != 0 || avail_out != CACHE_BUF_SIZE);
                    }
                }

                if (compress) {
                    compress_free(&comp_ctx);
                    fclose(comp_file_gz);
                    fclose(comp_file_br);
                    info("Finished compressing file %s", cache[i].filename);
                    strcpy(cache[i].meta.filename_comp_gz, filename_comp_gz);
                    strcpy(cache[i].meta.filename_comp_br, filename_comp_br);
                } else {
                    memset(cache[i].meta.filename_comp_gz, 0, sizeof(cache[i].meta.filename_comp_gz));
                    memset(cache[i].meta.filename_comp_br, 0, sizeof(cache[i].meta.filename_comp_br));
                }

                EVP_DigestFinal(ctx, hash, &md_len);
                EVP_MD_CTX_free(ctx);

                memset(cache[i].meta.etag, 0, sizeof(cache[i].meta.etag));
                for (int j = 0; j < md_len; j++) {
                    sprintf(cache[i].meta.etag + j * 2, "%02x", hash[j]);
                }
                fclose(file);
                info("Finished hashing file %s", cache[i].filename);
                cache[i].is_updating = 0;
                cache_changed = 1;
            }
        }

        if (cache_changed) {
            cache_changed = 0;
            cache_file = fopen("/var/sesimos/server/cache", "wb");
            if (cache_file == NULL) {
                critical("Unable to open cache file");
                return -1;
            }
            fwrite(cache, sizeof(cache_entry), CACHE_ENTRIES, cache_file);
            fclose(cache_file);
        } else {
            sleep(1);
        }
    }

    return 0;
}

int cache_init(void) {
    errno = 0;
    if (magic_init() != 0) {
        return -1;
    }

    int shm_id = shmget(CACHE_SHM_KEY, CACHE_ENTRIES * sizeof(cache_entry), IPC_CREAT | IPC_EXCL | 0600);
    if (shm_id < 0) {
        critical("Unable to create cache shared memory");
        return -2;
    }

    void *shm = shmat(shm_id, NULL, SHM_RDONLY);
    if (shm == (void *) -1) {
        critical("Unable to attach cache shared memory (ro)");
        return -3;
    }
    cache = shm;

    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        critical("Unable to attach cache shared memory (rw)");
        return -4;
    }
    cache = shm_rw;
    memset(cache, 0, CACHE_ENTRIES * sizeof(cache_entry));
    shmdt(shm_rw);
    cache = shm;
    errno = 0;

    pid_t pid = fork();
    if (pid == 0) {
        // child
        if (cache_process() == 0) {
            return 0;
        } else {
            return -6;
        }
    } else if (pid > 0) {
        // parent
        info("Started child process with PID %i as cache-updater", pid);
        return pid;
    } else {
        critical("Unable to create child process");
        return -5;
    }
}

int cache_unload(void) {
    int shm_id = shmget(CACHE_SHM_KEY, 0, 0);
    if (shm_id < 0) {
        critical("Unable to get cache shared memory id");
        shmdt(cache);
        return -1;
    } else if (shmctl(shm_id, IPC_RMID, NULL) < 0) {
        critical("Unable to configure cache shared memory");
        shmdt(cache);
        return -1;
    }
    shmdt(cache);
    errno = 0;
    return 0;
}

int cache_update_entry(int entry_num, const char *filename, const char *webroot) {
    void *cache_ro = cache;
    int shm_id = shmget(CACHE_SHM_KEY, 0, 0);
    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        error("Unable to attach cache shared memory (rw)");
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
    if (strncmp(type, "text/", 5) == 0) {
        if (strcmp(filename + strlen(filename) - 4, ".css") == 0) {
            sprintf(type_new, "text/css");
        } else if (strcmp(filename + strlen(filename) - 3, ".js") == 0) {
            sprintf(type_new, "application/javascript");
        }
    }
    strcpy(cache[entry_num].meta.type, type_new);

    magic_setflags(magic, MAGIC_MIME_ENCODING);
    strcpy(cache[entry_num].meta.charset, magic_file(magic, filename));

    memset(cache[entry_num].meta.etag, 0, sizeof(cache[entry_num].meta.etag));
    memset(cache[entry_num].meta.filename_comp_gz, 0, sizeof(cache[entry_num].meta.filename_comp_gz));
    memset(cache[entry_num].meta.filename_comp_br, 0, sizeof(cache[entry_num].meta.filename_comp_br));
    cache[entry_num].is_updating = 0;

    shmdt(shm_rw);
    cache = cache_ro;
    errno = 0;
    return 0;
}

int cache_filename_comp_invalid(const char *filename) {
    void *cache_ro = cache;
    int shm_id = shmget(CACHE_SHM_KEY, 0, 0);
    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        error("Unable to attach cache shared memory (rw)");
        return -1;
    }
    cache = shm_rw;

    int i;
    for (i = 0; i < CACHE_ENTRIES; i++) {
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
    memset(cache[i].meta.filename_comp_gz, 0, sizeof(cache[i].meta.filename_comp_gz));
    memset(cache[i].meta.filename_comp_br, 0, sizeof(cache[i].meta.filename_comp_br));
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
    for (i = 0; i < CACHE_ENTRIES; i++) {
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
        for (i = 0; i < CACHE_ENTRIES; i++) {
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
