/**
 * Necronda Web Server
 * URI and path handlers
 * src/lib/uri.c
 * Lorenz Stechauner, 2020-12-13
 */

#include "uri.h"
#include "utils.h"
#include <stdlib.h>
#include <string.h>

int path_is_directory(const char *path) {
    struct stat statbuf;
    return stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode) != 0;
}

int path_is_file(const char *path) {
    struct stat statbuf;
    return stat(path, &statbuf) == 0 && S_ISDIR(statbuf.st_mode) == 0;
}

int path_exists(const char *path) {
    struct stat statbuf;
    return stat(path, &statbuf) == 0;
}

int uri_init(http_uri *uri, const char *webroot, const char *uri_str, int dir_mode) {
    char buf0[1024];
    char buf1[1024];
    char buf2[1024];
    char buf3[1024];
    int p_len;
    uri->webroot = NULL;
    uri->req_path = NULL;
    uri->path = NULL;
    uri->pathinfo = NULL;
    uri->query = NULL;
    uri->filename = NULL;
    uri->uri = NULL;
    uri->meta = NULL;
    uri->is_static = 1;
    uri->is_dir = 0;
    if (uri_str[0] != '/') {
        return 1;
    }
    uri->webroot = malloc(strlen(webroot) + 1);
    strcpy(uri->webroot, webroot);

    char *query = strchr(uri_str, '?');
    if (query == NULL) {
        uri->query = NULL;
    } else {
        query[0] = 0;
        query++;
        long size = (long) strlen(query) + 1;
        uri->query = malloc(size);
        strcpy(uri->query, query);
    }

    long size = (long) strlen(uri_str) + 1;
    uri->req_path = malloc(size);
    url_decode(uri_str, uri->req_path, &size);
    if (query != NULL) {
        query[-1] = '?';
    }
    if (strstr(uri->req_path, "/../") != NULL || strstr(uri->req_path, "/./") != NULL) {
        return 2;
    }

    size = (long) strlen(uri->req_path) + 1;
    uri->path = malloc(size);
    uri->pathinfo = malloc(size);

    char last = 0;
    for (int i = 0, j = 0; i < size - 1; i++) {
        char ch = uri->req_path[i];
        if (last != '/' || ch != '/') {
            uri->path[j++] = ch;
            uri->path[j] = 0;
        }
        last = ch;
    }

    if (dir_mode == URI_DIR_MODE_NO_VALIDATION) {
        return 0;
    }

    if (uri->path[strlen(uri->path) - 1] == '/') {
        uri->path[strlen(uri->path) - 1] = 0;
        strcpy(uri->pathinfo, "/");
    } else {
        strcpy(uri->pathinfo, "");
    }

    if (!path_exists(uri->webroot)) {
        return 3;
    }

    while (1) {
        sprintf(buf0, "%s%s", uri->webroot, uri->path);
        p_len = snprintf(buf1, sizeof(buf1), "%s.php", buf0);
        if (p_len < 0 || p_len >= sizeof(buf1)) return -1;
        p_len = snprintf(buf2, sizeof(buf2), "%s.html", buf0);
        if (p_len < 0 || p_len >= sizeof(buf2)) return -1;

        if (strlen(uri->path) <= 1 || path_exists(buf0) || path_is_file(buf1) || path_is_file(buf2)) {
            break;
        }

        char *ptr;
        parent_dir:
        ptr = strrchr(uri->path, '/');
        size = (long) strlen(ptr);
        sprintf(buf3, "%.*s%s", (int) size, ptr, uri->pathinfo);
        strcpy(uri->pathinfo, buf3);
        ptr[0] = 0;
    }
    if (uri->pathinfo[0] != 0) {
        sprintf(buf3, "%s", uri->pathinfo + 1);
        strcpy(uri->pathinfo, buf3);
    }

    if (path_is_file(buf0)) {
        uri->filename = malloc(strlen(buf0) + 1);
        strcpy(uri->filename, buf0);
        long len = (long) strlen(uri->path);
        if (strcmp(uri->path + len - 5, ".html") == 0) {
            uri->path[len - 5] = 0;
        } else if (strcmp(uri->path + len - 4, ".php") == 0) {
            uri->path[len - 4] = 0;
            uri->is_static = 0;
        }
    } else if (path_is_file(buf1)) {
        uri->is_static = 0;
        uri->filename = malloc(strlen(buf1) + 1);
        strcpy(uri->filename, buf1);
    } else if (path_is_file(buf2)) {
        uri->filename = malloc(strlen(buf2) + 1);
        strcpy(uri->filename, buf2);
    } else {
        uri->is_dir = 1;
        strcpy(uri->path + strlen(uri->path), "/");
        sprintf(buf1, "%s%sindex.php", uri->webroot, uri->path);
        sprintf(buf2, "%s%sindex.html", uri->webroot, uri->path);
        if (path_is_file(buf1)) {
            uri->filename = malloc(strlen(buf1) + 1);
            strcpy(uri->filename, buf1);
            uri->is_static = 0;
        } else if (path_is_file(buf2)) {
            uri->filename = malloc(strlen(buf2) + 1);
            strcpy(uri->filename, buf2);
        } else {
            if (dir_mode == URI_DIR_MODE_FORBIDDEN) {
                uri->is_static = 1;
            } else if (dir_mode == URI_DIR_MODE_LIST) {
                uri->is_static = 0;
            } else if (dir_mode == URI_DIR_MODE_INFO) {
                if (strlen(uri->path) > 1) {
                    uri->path[strlen(uri->path) - 1] = 0;
                    sprintf(buf0, "/%s", uri->pathinfo);
                    strcpy(uri->pathinfo, buf0);
                    goto parent_dir;
                }
            }
        }
    }

    if (strcmp(uri->path + strlen(uri->path) - 5, "index") == 0) {
        uri->path[strlen(uri->path) - 5] = 0;
    }
    if (strcmp(uri->pathinfo, "index.php") == 0 || strcmp(uri->pathinfo, "index.html") == 0) {
        uri->pathinfo[0] = 0;
    }

    sprintf(buf0, "%s%s%s%s%s", uri->path,
            (strlen(uri->pathinfo) == 0 || uri->path[strlen(uri->path) - 1] == '/') ? "" : "/", uri->pathinfo,
            uri->query != NULL ? "?" : "", uri->query != NULL ? uri->query : "");
    uri->uri = malloc(strlen(buf0) + 1);
    strcpy(uri->uri, buf0);

    return 0;
}

void uri_free(http_uri *uri) {
    if (uri->webroot != NULL) free(uri->webroot);
    if (uri->req_path != NULL) free(uri->req_path);
    if (uri->path != NULL) free(uri->path);
    if (uri->pathinfo != NULL) free(uri->pathinfo);
    if (uri->query != NULL) free(uri->query);
    if (uri->filename != NULL) free(uri->filename);
    if (uri->uri != NULL) free(uri->uri);
    uri->webroot = NULL;
    uri->req_path = NULL;
    uri->path = NULL;
    uri->pathinfo = NULL;
    uri->query = NULL;
    uri->filename = NULL;
    uri->uri = NULL;
}
