/**
 * Necronda Web Server
 * URI and path handlers (header file)
 * src/uri.h
 * Lorenz Stechauner, 2020-12-13
 */

#ifndef NECRONDA_SERVER_URI_H
#define NECRONDA_SERVER_URI_H

#include <sys/stat.h>

#define URI_DIR_MODE_FORBIDDEN 0
#define URI_DIR_MODE_LIST 1
#define URI_DIR_MODE_INFO 2

typedef struct {
    char etag[64];
    char type[24];
    char charset[16];
    char filename_comp[256];
    struct stat stat;
} meta_data;

typedef struct {
    char *webroot;        // "/srv/www/www.test.org"
    char *req_path;       // "/account/login"
    char *path;           // "/account/"
    char *pathinfo;       // "login"
    char *query;          // "username=test"
    char *filename;       // "/account/index.php"
    char *uri;            // "/account/login?username=test"
    meta_data *meta;
    unsigned char is_static:1;
    unsigned char is_dir:1;
} http_uri;


int uri_init(http_uri *uri, const char *webroot, const char *uri_str, int dir_mode);

int uri_init_cache(http_uri *uri);

void uri_free(http_uri *uri);

#endif //NECRONDA_SERVER_URI_H
