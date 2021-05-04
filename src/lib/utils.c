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
    return
        strncmp(type, "text/", 5) == 0 ||
        strncmp(type, "message/", 7) == 0 ||
        strstr(type, "+xml") != NULL ||
        strstr(type, "+json") != NULL ||
        strcmp(type, "application/javascript") == 0 ||
        strcmp(type, "application/json") == 0 ||
        strcmp(type, "application/xml") == 0 ||
        strcmp(type, "application/x-www-form-urlencoded") == 0 ||
        strcmp(type, "application/x-tex") == 0 ||
        strcmp(type, "application/x-httpd-php") == 0 ||
        strcmp(type, "application/x-latex") == 0 ||
        strcmp(type, "application/vnd.ms-fontobject") == 0 ||
        strcmp(type, "application/x-font-ttf") == 0 ||
        strcmp(type, "application/x-javascript") == 0 ||
        strcmp(type, "application/x-web-app-manifest+json") == 0 ||
        strcmp(type, "font/eot") == 0 ||
        strcmp(type, "font/opentype") == 0 ||
        strcmp(type, "image/bmp") == 0 ||
        strcmp(type, "image/vnd.microsoft.icon") == 0 ||
        strcmp(type, "image/x-icon") == 0;
}
