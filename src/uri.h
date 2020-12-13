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
    char *uri;
    struct stat stat;
} uri;

#endif //NECRONDA_SERVER_URI_H
