/**
 * sesimos - secure, simple, modern web server
 * @brief File cache implementation
 * @file src/cache_handler.c
 * @author Lorenz Stechauner
 * @date 2020-12-19
 */

#include "logger.h"
#include "cache_handler.h"
#include "lib/utils.h"
#include "lib/compress.h"
#include "lib/config.h"

#include <stdio.h>
#include <magic.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <signal.h>

#define CACHE_BUF_SIZE 16

static magic_t magic;
static pthread_t thread;
static sem_t sem_free, sem_used, sem_lock, sem_cache, sem_magic;
volatile sig_atomic_t alive = 1;

typedef struct {
    int rd;
    int wr;
    cache_entry_t *msgs[CACHE_BUF_SIZE];
} buf_t;

static buf_t buffer;

static int magic_init(void) {
    if ((magic = magic_open(MAGIC_MIME)) == NULL) {
        critical("Unable to open magic cookie");
        return 1;
    }

    if (magic_load(magic, CACHE_MAGIC_FILE) != 0) {
        critical("Unable to load magic cookie: %s", magic_error(magic));
        return 1;
    }

    return 0;
}

static void magic_mime_type(const char *restrict filename, char *buf) {
    while (sem_wait(&sem_magic) != 0) {
        if (errno == EINTR) {
            errno = 0;
            continue;
        } else {
            critical("Unable to lock magic semaphore");
            return;
        }
    }

    magic_setflags(magic, MAGIC_MIME_TYPE);
    const char *type = magic_file(magic, filename);

    if (strstarts(type, "text/")) {
        if (strends(filename, ".css")) {
            strcpy(buf, "text/css");
            sem_post(&sem_magic);
            return;
        } else if (strends(filename, ".js")) {
            strcpy(buf, "application/javascript");
            sem_post(&sem_magic);
            return;
        }
    }

    strcpy(buf, type);
    sem_post(&sem_magic);
}

static void magic_charset(const char *restrict filename, char *buf) {
    while (sem_wait(&sem_magic) != 0) {
        if (errno == EINTR) {
            errno = 0;
            continue;
        } else {
            critical("Unable to lock magic semaphore");
            return;
        }
    }

    magic_setflags(magic, MAGIC_MIME_ENCODING);
    strcpy(buf, magic_file(magic, filename));
    sem_post(&sem_magic);
}

static void cache_free(void) {
    for (int i = 0; i < CONFIG_MAX_HOST_CONFIG; i++) {
        host_config_t *hc = &config.hosts[i];
        if (hc->type == CONFIG_TYPE_UNSET) break;
        if (hc->type != CONFIG_TYPE_LOCAL) continue;

        munmap(hc->cache, sizeof(cache_t));
    }

    magic_close(magic);

    sem_destroy(&sem_lock);
    sem_destroy(&sem_free);
    sem_destroy(&sem_used);
    sem_destroy(&sem_cache);
    sem_destroy(&sem_magic);
}

static cache_entry_t *cache_get_entry(cache_t *cache, const char *filename) {
    // search entry
    cache_entry_t *entry;
    for (int i = 0; i < CACHE_ENTRIES; i++) {
        entry = &cache->entries[i];
        if (entry->filename[0] == 0) break;
        if (streq(entry->filename, filename)) {
            // found
            return entry;
        }
    }

    // not found
    return NULL;
}

static cache_entry_t *cache_get_new_entry(cache_t *cache) {
    // globally lock cache
    while (sem_wait(&sem_cache) != 0) {
        if (errno == EINTR) {
            errno = 0;
            continue;
        } else {
            return NULL;
        }
    }

    // search empty slot
    cache_entry_t *entry;
    for (int i = 0; i < CACHE_ENTRIES; i++) {
        entry = &cache->entries[i];
        if (entry->filename[0] == 0) {
            // unlock cache
            sem_post(&sem_cache);
            return entry;
        }
    }

    // unlock cache
    sem_post(&sem_cache);

    // not found
    return NULL;
}

static void cache_process_entry(cache_entry_t *entry) {
    char buf[16384], comp_buf[16384], filename_comp_gz[256], filename_comp_br[256];

    info("Hashing file %s", entry->filename);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit(ctx, EVP_sha256());
    FILE *file = fopen(entry->filename, "rb");
    int compress = mime_is_compressible(entry->meta.type);

    compress_ctx comp_ctx;
    FILE *comp_file_gz = NULL, *comp_file_br = NULL;
    if (compress) {
        sprintf(buf, "%.*s/.sesimos", entry->webroot_len, entry->filename);
        if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
            error("Unable to create directory %s", buf);
            goto comp_err;
        }

        sprintf(buf, "%.*s/.sesimos/cache", entry->webroot_len, entry->filename);
        if (mkdir(buf, 0700) != 0 && errno != EEXIST) {
            error("Unable to create directory %s", buf);
            goto comp_err;
        }
        errno = 0;

        char *rel_path = entry->filename + entry->webroot_len + 1;
        for (int j = 0; j < strlen(rel_path); j++) {
            buf[j] = (char) ((rel_path[j] == '/') ? '_' : rel_path[j]);
        }
        buf[strlen(rel_path)] = 0;

        int p_len_gz = snprintf(filename_comp_gz, sizeof(filename_comp_gz),
                                "%.*s/.sesimos/cache/%s.gz",
                                entry->webroot_len, entry->filename, buf);
        int p_len_br = snprintf(filename_comp_br, sizeof(filename_comp_br),
                                "%.*s/.sesimos/cache/%s.br",
                                entry->webroot_len, entry->filename, buf);
        if (p_len_gz < 0 || p_len_gz >= sizeof(filename_comp_gz) || p_len_br < 0 || p_len_br >= sizeof(filename_comp_br)) {
            error("Unable to open cached file: File name for compressed file too long");
            goto comp_err;
        }

        info("Compressing file %s", entry->filename);

        comp_file_gz = fopen(filename_comp_gz, "wb");
        comp_file_br = fopen(filename_comp_br, "wb");
        if (comp_file_gz == NULL || comp_file_br == NULL) {
            error("Unable to open cached file");
            comp_err:
            compress = 0;
        } else {
            if ((compress_init(&comp_ctx, COMPRESS_GZ | COMPRESS_BR | (mime_is_text(entry->meta.type) ? COMPRESS_UTF8 : 0))) != 0) {
                error("Unable to init compression");
                compress = 0;
                fclose(comp_file_gz);
                fclose(comp_file_br);
            }
        }
    }

    for (unsigned long read, avail_in, avail_out; (read = fread(buf, 1, sizeof(buf), file)) > 0;) {
        EVP_DigestUpdate(ctx, buf, read);
        if (compress) {
            avail_in = read;
            do {
                avail_out = sizeof(comp_buf);
                compress_compress_mode(&comp_ctx, COMPRESS_GZ, buf + read - avail_in, &avail_in, comp_buf, &avail_out, feof(file));
                fwrite(comp_buf, 1, sizeof(comp_buf) - avail_out, comp_file_gz);
            } while (avail_in != 0 || avail_out != sizeof(comp_buf));
            avail_in = read;
            do {
                avail_out = sizeof(comp_buf);
                compress_compress_mode(&comp_ctx, COMPRESS_BR, buf + read - avail_in, &avail_in, comp_buf, &avail_out, feof(file));
                fwrite(comp_buf, 1, sizeof(comp_buf) - avail_out, comp_file_br);
            } while (avail_in != 0 || avail_out != sizeof(comp_buf));
        }
    }

    if (compress) {
        compress_free(&comp_ctx);
        fclose(comp_file_gz);
        fclose(comp_file_br);
        info("Finished compressing file %s", entry->filename);
        strcpy(entry->meta.filename_comp_gz, filename_comp_gz);
        strcpy(entry->meta.filename_comp_br, filename_comp_br);
    } else {
        memset(entry->meta.filename_comp_gz, 0, sizeof(entry->meta.filename_comp_gz));
        memset(entry->meta.filename_comp_br, 0, sizeof(entry->meta.filename_comp_br));
    }

    unsigned int md_len;
    unsigned char hash[EVP_MAX_MD_SIZE];
    EVP_DigestFinal(ctx, hash, &md_len);
    EVP_MD_CTX_free(ctx);

    memset(entry->meta.etag, 0, sizeof(entry->meta.etag));
    for (int j = 0; j < md_len; j++) {
        sprintf(entry->meta.etag + j * 2, "%02x", hash[j]);
    }
    fclose(file);
    entry->flags &= !CACHE_DIRTY;

    info("Finished hashing file %s", entry->filename);
}

static void *cache_thread(void *arg) {
    logger_set_name("cache");

    while (alive) {
        pthread_testcancel();
        if (sem_wait(&sem_used) != 0) {
            if (errno == EINTR) {
                errno = 0;
                continue;
            } else {
                error("Unable to lock semaphore");
                errno = 0;
                break;
            }
        }

        cache_entry_t *entry = buffer.msgs[buffer.wr];
        buffer.wr = (buffer.wr + 1) % CACHE_BUF_SIZE;

        cache_process_entry(entry);

        // unlock slot in buffer
        sem_post(&sem_free);
    }

    cache_free();

    return NULL;
}

int cache_init(void) {
    char buf[512];
    int ret, fd;
    if ((ret = magic_init()) != 0)
        return ret;

    for (int i = 0; i < CONFIG_MAX_HOST_CONFIG; i++) {
        host_config_t *hc = &config.hosts[i];
        if (hc->type == CONFIG_TYPE_UNSET) break;
        if (hc->type != CONFIG_TYPE_LOCAL) continue;

        sprintf(buf, "%s/.sesimos", hc->local.webroot);
        if (mkdir(buf, 0755) != 0 && errno != EEXIST) {
            critical("Unable to create directory %s", buf);
            return 1;
        }
        errno = 0;

        sprintf(buf, "%s/.sesimos/metadata", hc->local.webroot);
        if ((fd = open(buf, O_CREAT | O_RDWR, 0600)) == -1) {
            critical("Unable to open file %s", buf);
            return 1;
        }

        if (ftruncate(fd, sizeof(cache_t)) == -1) {
            critical("Unable to truncate file %s", buf);
            return 1;
        }

        if ((hc->cache = mmap(NULL, sizeof(cache_t), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0)) == NULL) {
            critical("Unable to map file %s", buf);
            close(fd);
            return 1;
        }

        close(fd);
        errno = 0;
    }

    // try to initialize all three semaphores
    if (sem_init(&sem_lock, 0, 1) != 0 ||
        sem_init(&sem_free, 0, 1) != 0 ||
        sem_init(&sem_used, 0, 0) != 0 ||
        sem_init(&sem_cache, 0, 1) != 0 ||
        sem_init(&sem_magic, 0, 1) != 0)
    {
        critical("Unable to initialize semaphore");
        return -1;
    }

    // initialize read/write heads
    buffer.rd = 0;
    buffer.wr = 0;

    pthread_create(&thread, NULL, cache_thread, NULL);

    return 0;
}

void cache_stop(void) {
    alive = 0;
    pthread_kill(thread, SIGUSR1);
}

int cache_join(void) {
    return pthread_join(thread, NULL);
}

static void cache_mark_entry_dirty(cache_entry_t *entry) {
    if (entry->flags & CACHE_DIRTY)
        return;

    entry->flags |= CACHE_DIRTY;
    memset(entry->meta.etag, 0, sizeof(entry->meta.etag));
    memset(entry->meta.filename_comp_gz, 0, sizeof(entry->meta.filename_comp_gz));
    memset(entry->meta.filename_comp_br, 0, sizeof(entry->meta.filename_comp_br));

    while (sem_wait(&sem_free) != 0) {
        if (errno == EINTR) {
            errno = 0;
            continue;
        } else {
            error("Unable to lock semaphore");
            errno = 0;
        }
        return;
    }

    // try to lock buffer
    while (sem_wait(&sem_lock) != 0) {
        if (errno == EINTR) {
            errno = 0;
            continue;
        } else {
            error("Unable to lock semaphore");
            errno = 0;
        }
        return;
    }

    // write to buffer
    buffer.msgs[buffer.rd] = entry;
    buffer.rd = (buffer.rd + 1) % CACHE_BUF_SIZE;

    // unlock buffer
    sem_post(&sem_lock);

    // unlock slot in buffer for logger
    sem_post(&sem_used);
}

static void cache_update_entry(cache_entry_t *entry, const char *filename, const char *webroot) {
    entry->meta.mtime = stat_mtime(filename);
    entry->webroot_len = (unsigned char) strlen(webroot);
    strcpy(entry->filename, filename);

    magic_mime_type(filename, entry->meta.type);
    magic_charset(filename, entry->meta.charset);

    cache_mark_entry_dirty(entry);
}

void cache_mark_dirty(cache_t *cache, const char *filename) {
    cache_entry_t *entry = cache_get_entry(cache, filename);
    if (entry) cache_mark_entry_dirty(entry);
}

void cache_init_uri(cache_t *cache, http_uri *uri) {
    if (!uri->filename)
        return;

    cache_entry_t *entry = cache_get_entry(cache, uri->filename);
    if (!entry) {
        // no entry found -> create new entry
        if ((entry = cache_get_new_entry(cache))) {
            cache_update_entry(entry, uri->filename, uri->webroot);
            uri->meta = &entry->meta;
        } else {
            warning("No empty cache entry slot found");
        }
    } else {
        uri->meta = &entry->meta;
        if (entry->flags & CACHE_DIRTY)
            return;

        // check, if file has changed
        if (uri->meta->mtime != stat_mtime(uri->filename)) {
            // modify time has changed
            cache_update_entry(entry, uri->filename, uri->webroot);
        }
    }
}
