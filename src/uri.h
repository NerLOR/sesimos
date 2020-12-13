/**
 * Necronda Web Server
 * URI and path handlers (header file)
 * src/uri.h
 * Lorenz Stechauner, 2020-12-13
 */

#ifndef NECRONDA_SERVER_URI_H
#define NECRONDA_SERVER_URI_H

#include <sys/stat.h>

typedef struct {
    char *webroot;
    char *path;
    char *pathinfo;
    char *query;
    char *filename;
    char *filename_comp;
    char *uri;
    struct stat stat;
    int is_static:1;
} http_uri;


int uri_init(http_uri *uri, const char *webroot, const char *uri_str);

void uri_free(http_uri *uri);

#endif //NECRONDA_SERVER_URI_H
