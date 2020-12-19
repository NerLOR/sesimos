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
    magic_load(magic, "/usr/share/misc/magic.mgc");
    return 0;
}

int cache_init() {
    magic_init();

    return 0;
}

int uri_cache_init(http_uri *uri) {
    if (uri->filename == NULL) {
        return -1;
    }



    return 0;
}
