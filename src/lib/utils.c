/**
 * Necronda Web Server
 * Utilities
 * src/lib/utils.c
 * Lorenz Stechauner, 2020-12-03
 */

#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char *log_prefix;

char *format_duration(unsigned long micros, char *buf) {
    if (micros < 10000) {
        sprintf(buf, "%.1f ms", (double) micros / 1000);
    } else if (micros < 1000000) {
        sprintf(buf, "%li ms", micros / 1000);
    } else if (micros < 60000000) {
        sprintf(buf, "%.1f s", (double) micros / 1000000);
    } else if (micros < 6000000000) {
        sprintf(buf, "%.1f min", (double) micros / 1000000 / 60);
    } else {
        sprintf(buf, "%li min", micros / 1000000 / 60);
    }
    return buf;
}

int url_encode_component(const char *str, char *enc, long *size) {
    char *ptr = enc;
    char ch;
    memset(enc, 0, *size);
    for (int i = 0; i < strlen(str); i++, ptr++) {
        if ((ptr - enc) >= *size) {
            return -1;
        }
        ch = str[i];
        if (ch == ':' || ch == '/' || ch == '?' || ch == '#' || ch == '[' || ch == ']' || ch == '@' || ch == '!' ||
                ch == '$' || ch == '&' || ch == '\'' || ch == '(' || ch == ')' || ch == '*' || ch == '+' || ch == ',' ||
                ch == ';' || ch == '=' || ch < ' ' || ch > '~') {
            if ((ptr - enc + 2) >= *size) {
                return -1;
            }
            sprintf(ptr, "%%%02X", ch);
            ptr += 2;
        } else if (ch == ' ') {
            ptr[0] = '+';
        } else {
            ptr[0] = ch;
        }
    }
    *size = ptr - enc;
    return 0;
}

int url_encode(const char *str, char *enc, long *size) {
    char *ptr = enc;
    unsigned char ch;
    memset(enc, 0, *size);
    for (int i = 0; i < strlen(str); i++, ptr++) {
        if ((ptr - enc) >= *size) {
            return -1;
        }
        ch = str[i];
        if (ch > 0x7F || ch == ' ') {
            if ((ptr - enc + 2) >= *size) {
                return -1;
            }
            sprintf(ptr, "%%%02X", ch);
            ptr += 2;
        } else {
            ptr[0] = (char) ch;
        }
    }
    *size = ptr - enc;
    return 0;
}

int url_decode(const char *str, char *dec, long *size) {
    char *ptr = dec;
    char ch, buf[3];
    memset(dec, 0, *size);
    for (int i = 0; i < strlen(str); i++, ptr++) {
        if ((ptr - dec) >= *size) {
            return -1;
        }
        ch = str[i];
        if (ch == '+') {
            ch = ' ';
        } else if (ch == '%') {
            memcpy(buf, str + i + 1, 2);
            buf[2] = 0;
            ch = (char) strtol(buf, NULL, 16);
            i += 2;
        } else if (ch == '?') {
            strcpy(ptr, str + i);
            break;
        }
        ptr[0] = ch;
    }
    *size = ptr - dec;
    return 0;
}

int mime_is_compressible(const char *type) {
    if (type == NULL) return 0;
    char type_parsed[64];
    snprintf(type_parsed, sizeof(type_parsed), "%s", type);
    char *pos = strchr(type_parsed, ';');
    if (pos != NULL) pos[0] = 0;
    return
        strncmp(type_parsed, "text/", 5) == 0 ||
        strncmp(type_parsed, "message/", 7) == 0 ||
        strstr(type_parsed, "+xml") != NULL ||
        strstr(type_parsed, "+json") != NULL ||
        strcmp(type_parsed, "application/javascript") == 0 ||
        strcmp(type_parsed, "application/json") == 0 ||
        strcmp(type_parsed, "application/xml") == 0 ||
        strcmp(type_parsed, "application/x-www-form-urlencoded") == 0 ||
        strcmp(type_parsed, "application/x-tex") == 0 ||
        strcmp(type_parsed, "application/x-httpd-php") == 0 ||
        strcmp(type_parsed, "application/x-latex") == 0 ||
        strcmp(type_parsed, "application/vnd.ms-fontobject") == 0 ||
        strcmp(type_parsed, "application/x-font-ttf") == 0 ||
        strcmp(type_parsed, "application/x-javascript") == 0 ||
        strcmp(type_parsed, "application/x-web-app-manifest+json") == 0 ||
        strcmp(type_parsed, "font/eot") == 0 ||
        strcmp(type_parsed, "font/opentype") == 0 ||
        strcmp(type_parsed, "image/bmp") == 0 ||
        strcmp(type_parsed, "image/vnd.microsoft.icon") == 0 ||
        strcmp(type_parsed, "image/vnd.microsoft.iconbinary") == 0 ||
        strcmp(type_parsed, "image/x-icon") == 0;
}

int strcpy_rem_webroot(char *dst, const char *src, long len, const char *webroot) {
    strncpy(dst, src, len);
    if (webroot == NULL) return 0;
    char *pos;
    while ((pos = strstr(dst, webroot)) != NULL) {
        strcpy(pos, pos + strlen(webroot));
    }
    return 0;
}
