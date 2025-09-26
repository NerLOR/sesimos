/**
 * sesimos - secure, simple, modern web server
 * @brief Utilities
 * @file src/lib/utils.c
 * @author Lorenz Stechauner
 * @date 2020-12-03
 */

#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h>
#include <errno.h>
#include <unistd.h>
#include <dirent.h>


static const char base64_encode_table[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const int base64_mod_table[3] = {0, 2, 1};
static const char base64_decode_table[256] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1,  0, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};


char *format_duration(unsigned long micros, char *buf) {
    if (micros < 10000) {
        sprintf(buf, "%.1f ms", (double) micros / 1000);
    } else if (micros < 1000000 - 1000) {
        sprintf(buf, "%.0f ms", (double) micros / 1000);
    } else if (micros < 60000000 - 1000000) {
        sprintf(buf, "%.1f s", (double) micros / 1000000);
    } else if (micros < 6000000000) {
        sprintf(buf, "%li:%02li min", micros / 1000000 / 60, micros / 1000000 % 60);
    } else {
        sprintf(buf, "%.0f min", (double) micros / 1000000 / 60);
    }
    return buf;
}

int url_encode_component(const void *in, size_t size_in, char *out, size_t size_out) {
    int size = 0;

    // Encode control characters
    for (int i = 0; i < size_in; i++) {
        unsigned char ch = ((unsigned char *) in)[i];
        if (ch == ' ') {
            ch = '+';
        } else if (
                ch <= 0x20 || ch >= 0x7F ||
                !((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
                  ch == '-' || ch == '_' || ch == '.' || ch == '!' || ch == '~' || ch == '*' || ch == '\'' ||
                  ch == '(' || ch == ')')
        ) {
            size += 3;
            if (size < size_out) sprintf(out + size - 3, "%%%02X", ch);
            ch = 0;
        }

        if (ch != 0) {
            size++;
            if (size < size_out) out[size - 1] = (char) ch;
        }
    }

    // Set terminating null byte
    if (size_out > 0) out[size < size_out ? size : size_out - 1] = 0;

    // Return theoretical size
    return size;
}

int url_encode(const void *in, size_t size_in, char *out, size_t size_out) {
    int size = 0;

    // Encode control characters
    for (int i = 0; i < size_in; i++) {
        unsigned char ch = ((unsigned char *) in)[i];
        if (ch <= 0x20 || ch >= 0x7F) {
            size += 3;
            if (size < size_out) sprintf(out + size - 3, "%%%02X", ch);
        } else {
            size++;
            if (size < size_out) out[size - 1] = (char) ch;
        }
    }

    // Set terminating null byte
    if (size_out > 0) out[size < size_out ? size : size_out - 1] = 0;

    // Return theoretical size
    return size;
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

int mime_is_compressible(const char *restrict type) {
    if (type == NULL) return 0;
    char type_parsed[64];
    snprintf(type_parsed, sizeof(type_parsed), "%s", type);
    char *pos = strchr(type_parsed, ';');
    if (pos != NULL) pos[0] = 0;
    return
        mime_is_text(type) ||
        streq(type_parsed, "application/vnd.ms-fontobject") ||
        streq(type_parsed, "application/x-font-ttf") ||
        streq(type_parsed, "font/eot") ||
        streq(type_parsed, "font/opentype") ||
        streq(type_parsed, "image/bmp") ||
        streq(type_parsed, "image/gif") ||
        streq(type_parsed, "image/vnd.microsoft.icon") ||
        streq(type_parsed, "image/vnd.microsoft.iconbinary") ||
        streq(type_parsed, "image/x-icon");
}

int mime_is_text(const char *restrict type) {
    if (type == NULL) return 0;
    char type_parsed[64];
    snprintf(type_parsed, sizeof(type_parsed), "%s", type);
    char *pos = strchr(type_parsed, ';');
    if (pos != NULL) pos[0] = 0;
    return
        strstarts(type_parsed, "text/") ||
        strstarts(type_parsed, "message/") ||
        strends(type_parsed, "+xml") ||
        strends(type_parsed, "+json") ||
        streq(type_parsed, "application/javascript") ||
        streq(type_parsed, "application/json") ||
        streq(type_parsed, "application/xml") ||
        streq(type_parsed, "application/sql") ||
        streq(type_parsed, "application/x-www-form-urlencoded") ||
        streq(type_parsed, "application/x-tex") ||
        streq(type_parsed, "application/x-httpd-php") ||
        streq(type_parsed, "application/x-latex") ||
        streq(type_parsed, "application/x-javascript");
}

int strcpy_rem_webroot(char *dst, const char *src, const char *webroot) {
    strcpy(dst, src);
    if (webroot == NULL)
        return 0;

    char *pos;
    const unsigned long webroot_len = strlen(webroot);
    if (webroot_len == 0)
        return 0;

    while ((pos = strstr(dst, webroot)) != NULL) {
        strcpy(pos, pos + webroot_len);
    }

    return 0;
}

int str_trim(char **start, char **end) {
    if (start == NULL || end == NULL || *start == NULL || *end == NULL)
        return -1;

    (*end)--;
    while (*start[0] == ' ' || *start[0] == '\t' || *start[0] == '\r' || *start[0] == '\n') (*start)++;
    while (*end[0] == ' ' || *end[0] == '\t' || *end[0] == '\r' || *end[0] == '\n') (*end)--;
    (*end)++;
    return 0;
}

int str_trim_lws(char **start, char **end) {
    if (start == NULL || end == NULL || *start == NULL || *end == NULL)
        return -1;

    (*end)--;
    while (*start[0] == ' ' || *start[0] == '\t') (*start)++;
    while (*end[0] == ' ' || *end[0] == '\t') (*end)--;
    (*end)++;
    return 0;
}

int streq(const char *restrict str1, const char *restrict str2) {
    return str1 != NULL && str2 != NULL && strcmp(str1, str2) == 0;
}

int strcontains(const char *restrict haystack, const char *restrict needle) {
    return haystack != NULL && needle != NULL && strstr(haystack, needle) != NULL;
}

int strstarts(const char *restrict str, const char *restrict prefix) {
    if (str == NULL || prefix == NULL) return 0;
    const unsigned long l1 = strlen(str), l2 = strlen(prefix);
    return l2 <= l1 && strncmp(str, prefix, l2) == 0;
}

int strends(const char *restrict str, const char *restrict suffix) {
    if (str == NULL || suffix == NULL) return 0;
    const unsigned long l1 = strlen(str), l2 = strlen(suffix);
    return l2 <= l1 && strcmp(str + l1 - l2, suffix) == 0;
}

int base64_encode(void *data, unsigned long data_len, char *output, unsigned long *output_len) {
    const unsigned long out_len = 4 * ((data_len + 2) / 3);
    if (output_len != NULL) *output_len = out_len;

    for (int i = 0, j = 0; i < data_len;) {
        const unsigned int octet_a = (i < data_len) ? ((unsigned char *) data)[i++] : 0;
        const unsigned int octet_b = (i < data_len) ? ((unsigned char *) data)[i++] : 0;
        const unsigned int octet_c = (i < data_len) ? ((unsigned char *) data)[i++] : 0;
        const unsigned int triple = (octet_a << 16) | (octet_b << 8) | octet_c;
        output[j++] = base64_encode_table[(triple >> 3 * 6) & 0x3F];
        output[j++] = base64_encode_table[(triple >> 2 * 6) & 0x3F];
        output[j++] = base64_encode_table[(triple >> 1 * 6) & 0x3F];
        output[j++] = base64_encode_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < base64_mod_table[data_len % 3]; i++)
        output[out_len - 1 - i] = '=';
    output[out_len] = 0;

    return 0;
}

int base64_decode(const char *data, unsigned long data_len, void *output, unsigned long *output_len) {
    const unsigned long out_len = 3 * ((data_len + 2) / 4);
    if (output_len != NULL) *output_len = out_len;

    char *out = output;
    for (int i = 0, j = 0; i < data_len;) {
        const int octet_a = (i < data_len) ? base64_decode_table[((unsigned char *) data)[i++]] : 0;
        const int octet_b = (i < data_len) ? base64_decode_table[((unsigned char *) data)[i++]] : 0;
        const int octet_c = (i < data_len) ? base64_decode_table[((unsigned char *) data)[i++]] : 0;
        const int octet_d = (i < data_len) ? base64_decode_table[((unsigned char *) data)[i++]] : 0;
        if (octet_a < 0 || octet_b < 0 || octet_c < 0 || octet_d < 0) return -1;
        const unsigned int triple = (octet_a << 3 * 6) | (octet_b << 2 * 6) | (octet_c << 6) | octet_d;
        out[j++] = (char) (triple >> 16);
        out[j++] = (char) ((triple >> 8) & 0xFF);
        out[j++] = (char) (triple & 0xFF);
    }

    out[out_len] = 0;

    return 0;
}

long clock_micros(void) {
    struct timespec time;
    clock_gettime(CLOCK_MONOTONIC, &time);
    return time.tv_sec * 1000000 + time.tv_nsec / 1000;
}

long clock_cpu(void) {
    struct timespec time;
    clock_gettime(CLOCK_THREAD_CPUTIME_ID, &time);
    return time.tv_sec * 1000000000 + time.tv_nsec;
}

long stat_mtime(const char *filename) {
    struct stat stat_buf;
    stat(filename, &stat_buf);
    return stat_buf.st_mtime;
}

int rm_rf(const char *path) {
    struct stat stat_buf;
    if (lstat(path, &stat_buf) != 0)
        return (errno == ENOENT) ? 0 : -1;

    if (S_ISREG(stat_buf.st_mode)) {
        // regular file
        return unlink(path);
    } else if (S_ISLNK(stat_buf.st_mode)) {
        // link
        return unlink(path);
    } else if (S_ISDIR(stat_buf.st_mode)) {
        // directory
        char buf[FILENAME_MAX];
        DIR *dir;

        // open directory
        if ((dir = opendir(path)) == NULL)
            return -1;

        // read directory
        for (struct dirent *ent; (ent = readdir(dir)) != NULL;) {
            if (streq(ent->d_name, ".") || streq(ent->d_name, ".."))
                continue;

            snprintf(buf, sizeof(buf), "%s/%s", path, ent->d_name);
            if (rm_rf(buf) != 0) {
                closedir(dir);
                return -1;
            }
        }

        // close and remove directory
        closedir(dir);
        return rmdir(path);
    } else {
        // other - not supported
        errno = ENOTSUP;
        return -1;
    }
}

long fsize(FILE *file) {
    long cur_pos, len;
    if ((cur_pos = ftell(file)) == -1)
        return -1;
    if (fseek(file, 0, SEEK_END) != 0)
        return -1;
    if ((len = ftell(file)) == -1)
        return -1;
    if (fseek(file, cur_pos, SEEK_SET) != 0)
        return -1;
    return len;
}

long flines(FILE *file) {
    long cur_pos, lines = 0;
    if ((cur_pos = ftell(file)) == -1)
        return -1;
    if (fseek(file, 0, SEEK_SET) != 0)
        return -1;

    for (int ch; (ch = fgetc(file)) != EOF;) {
        if (ch == '\n') lines++;
    }

    if (fseek(file, cur_pos, SEEK_SET) != 0)
        return -1;
    return lines + 1;
}

long file_get_line_pos(FILE *file, long line_num) {
    if (line_num < 1) {
        errno = EINVAL;
        return -1;
    }

    long cur_pos;
    if ((cur_pos = ftell(file)) == -1)
        return -1;
    if (fseek(file, 0, SEEK_SET) != 0)
        return -1;

    long lines = 0, pos = 0;
    for (int ch; lines < line_num - 1 && (ch = fgetc(file)) != EOF; pos++) {
        if (ch == '\n') lines++;
    }

    if (fseek(file, cur_pos, SEEK_SET) != 0)
        return -1;
    return pos;
}

int fseekl(FILE *file, long line_num) {
    if (line_num < 1) {
        errno = EINVAL;
        return -1;
    }

    if (fseek(file, 0, SEEK_SET) != 0)
        return -1;

    long lines = 0;
    for (int ch; lines < line_num - 1 && (ch = fgetc(file)) != EOF;) {
        if (ch == '\n') lines++;
    }

    return 0;
}

long ftelll(FILE *file) {
    long cur_pos;
    if ((cur_pos = ftell(file)) == -1)
        return -1;
    if (fseek(file, 0, SEEK_SET) != 0)
        return -1;

    long lines = 0, pos = 0;
    for (int ch; pos < cur_pos && (ch = fgetc(file)) != EOF; pos++) {
        if (ch == '\n') lines++;
    }

    if (fseek(file, cur_pos, SEEK_SET) != 0)
        return -1;
    return lines + 1;
}

long parse_chunk_header(const char *buf, size_t len, size_t *ret_len) {
    for (int i = 0; i < len; i++) {
        char ch = buf[i];
        if (ch == '\r') {
            continue;
        } else if (ch == '\n' && i > 1 && buf[i - 1] == '\r') {
            if (ret_len != NULL) *ret_len = i + 1;
            return strtol(buf, NULL, 16);
        } else if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F'))) {
            errno = EPROTO;
            return -1;
        }
    }
    return -1;
}
