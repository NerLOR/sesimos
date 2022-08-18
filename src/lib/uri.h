/**
 * sesimos - secure, simple, modern web server
 * URI and path handlers (header file)
 * src/lib/uri.h
 * Lorenz Stechauner, 2020-12-13
 */

#ifndef SESIMOS_URI_H
#define SESIMOS_URI_H

#include <sys/stat.h>

#define URI_DIR_MODE_NO_VALIDATION 0
#define URI_DIR_MODE_FORBIDDEN 1
#define URI_DIR_MODE_LIST 2
#define URI_DIR_MODE_INFO 3

typedef struct {
    char etag[64];
    char type[24];
    char charset[16];
    char filename_comp_gz[256];
    char filename_comp_br[256];
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

#endif //SESIMOS_URI_H
