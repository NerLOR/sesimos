/**
 * sesimos - secure, simple, modern web server
 * @brief URI and path handlers (header file)
 * @file src/lib/uri.h
 * @author Lorenz Stechauner
 * @date 2020-12-13
 */

#ifndef SESIMOS_URI_H
#define SESIMOS_URI_H

#include <sys/stat.h>

#define URI_DIR_MODE_NO_VALIDATION 0
#define URI_DIR_MODE_FORBIDDEN 1
#define URI_DIR_MODE_LIST 2
#define URI_DIR_MODE_INFO 3

#define URI_ETAG_SIZE 64  // SHA256 size (hex)
#define URI_TYPE_SIZE 64
#define URI_CHARSET_SIZE 16

typedef struct {
    char etag[URI_ETAG_SIZE];
    char type[URI_TYPE_SIZE];
    char charset[URI_CHARSET_SIZE];
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
    unsigned int is_static:1;
    unsigned int is_dir:1;
} http_uri;


int uri_init(http_uri *uri, const char *webroot, const char *uri_str, int dir_mode);

int uri_init_cache(http_uri *uri);

void uri_free(http_uri *uri);

#endif //SESIMOS_URI_H
