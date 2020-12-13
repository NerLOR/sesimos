/**
 * Necronda Web Server
 * URI and path handlers
 * src/uri.c
 * Lorenz Stechauner, 2020-12-13
 */

#include "uri.h"


int uri_init(http_uri *uri, const char *webroot, const char *uri_str) {
    uri->webroot = malloc(strlen(webroot) + 1);
    strcpy(uri->webroot, webroot);

    char* query = strchr(uri_str, '?');
    if (query == NULL) {
        uri->query = NULL;
    } else {
        query[0] = 0;
        query++;
        ssize_t size = strlen(query) + 1;
        uri->query = malloc(size);
        url_decode(query, uri->query, &size);
    }

    ssize_t size = strlen(uri_str) + 1;
    char *uri_dec = malloc(size);
    url_decode(uri_str, uri_dec, &size);

    return 0;
}

void uri_free(http_uri *uri) {
    free(uri->webroot);
    free(uri->path);
    free(uri->pathinfo);
    if (uri->query != NULL) free(uri->query);
    free(uri->filename);
    free(uri->uri);
}
