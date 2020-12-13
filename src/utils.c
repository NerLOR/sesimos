/**
 * Necronda Web Server
 * Utilities
 * src/utils.c
 * Lorenz Stechauner, 2020-12-03
 */

#include "utils.h"

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

int url_encode(const char *str, char *enc, ssize_t *size) {
    char *ptr = enc;
    char ch;
    memset(enc, 0, *size);
    for (int i = 0; i < strlen(str); i++, ptr++) {
        if ((ptr - enc) >= *size) {
            printf("%li %li\n", ptr - enc, *size);
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

int url_decode(const char *str, char *dec, ssize_t *size) {
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
        }
        ptr[0] = ch;
    }
    *size = ptr - dec;
    return 0;
}
