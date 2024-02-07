/**
 * sesimos - secure, simple, modern web server
 * @brief HTTP implementation
 * @file src/lib/http.c
 * @author Lorenz Stechauner
 * @date 2020-12-09
 */

#include "http.h"
#include "utils.h"
#include "compress.h"
#include "list.h"
#include "error.h"

#include <string.h>
#include <errno.h>

void http_append_to_header_field(http_field *field, const char *value, unsigned long len);

static int http_error(int err) {
    if (err == 0) {
        errno = 0;
    } else if (err == HTTP_ERROR_SYSCALL) {
        // errno already set
    } else {
        error_http(err);
    }
    return -1;
}

const char *http_error_str(int err) {
    switch (err) {
        case HTTP_ERROR_TOO_MANY_HEADER_FIELDS:
            return "too many header fields";
        case HTTP_ERROR_EOH_NOT_FOUND:
            return "end of http header not found";
        case HTTP_ERROR_HEADER_MALFORMED:
            return "http header malformed";
        case HTTP_ERROR_INVALID_VERSION:
            return "invalid http version";
        case HTTP_ERROR_URI_TOO_LONG:
            return "uri too long";
        case HTTP_ERROR_GENERAL:
        default:
            return "unknown error";
    }
}

void http_to_camel_case(char *str, int mode) {
    if (mode == HTTP_PRESERVE)
        return;

    char ch, last = '-';
    for (int i = 0; i < strlen(str); i++) {
        ch = str[i];
        if (mode == HTTP_CAMEL && last == '-' && ch >= 'a' && ch <= 'z') {
            str[i] = (char) ((int) ch & 0x5F);
        } else if (mode == HTTP_LOWER && ch >= 'A' && ch <= 'Z') {
            str[i] = (char) ((int) ch | 0x20);
        }
        last = str[i];
    }
}

const char *http_field_get_name(const http_field *field) {
    if (field->type == HTTP_FIELD_NORMAL) {
        return field->normal.name;
    } else if (field->type == HTTP_FIELD_EX_VALUE) {
        return field->ex_value.name;
    } else if (field->type == HTTP_FIELD_EX_NAME) {
        return field->ex_name.name;
    }
    return NULL;
}

const char *http_field_get_value(const http_field *field) {
    if (field->type == HTTP_FIELD_NORMAL) {
        return field->normal.value;
    } else if (field->type == HTTP_FIELD_EX_VALUE) {
        return field->ex_value.value;
    } else if (field->type == HTTP_FIELD_EX_NAME) {
        return field->ex_name.value;
    }
    return NULL;
}

void http_free_field(http_field *f) {
    if (f->type == HTTP_FIELD_NORMAL) {
        f->normal.name[0] = 0;
        f->normal.value[0] = 0;
    } else if (f->type == HTTP_FIELD_EX_VALUE) {
        f->ex_value.name[0] = 0;
        free(f->ex_value.value);
        f->ex_value.value = NULL;
    } else if (f->type == HTTP_FIELD_EX_NAME) {
        free(f->ex_name.name);
        free(f->ex_name.value);
        f->ex_name.name = NULL;
        f->ex_name.value = NULL;
    }
}

void http_free_hdr(http_hdr *hdr) {
    for (int i = 0; i < list_size(hdr->fields); i++) {
        http_free_field(&hdr->fields[i]);
    }
    list_free(hdr->fields);
    hdr->last_field_num = -1;
}

void http_free_req(http_req *req) {
    if (req->uri != NULL) free(req->uri);
    req->uri = NULL;
    http_free_hdr(&req->hdr);
}

void http_free_res(http_res *res) {
    http_free_hdr(&res->hdr);
}

int http_init_hdr(http_hdr *hdr) {
    hdr->last_field_num = -1;
    hdr->fields = list_create(sizeof(http_field), HTTP_INIT_HEADER_FIELD_NUM);
    if (hdr->fields == NULL)
        return http_error(HTTP_ERROR_SYSCALL);

    return 0;
}

int http_parse_header_field(http_hdr *hdr, const char *buf, const char *end_ptr, int flags) {
    if (hdr->last_field_num > list_size(hdr->fields))
        return http_error(HTTP_ERROR_GENERAL);

    char *pos1 = (char *) buf, *pos2 = (char *) end_ptr;
    if (buf[0] == ' ' || buf[0] == '\t') {
        if (hdr->last_field_num == -1)
            return http_error(HTTP_ERROR_GENERAL);

        http_field *f = &hdr->fields[(int) hdr->last_field_num];

        str_trim_lws(&pos1, &pos2);
        http_append_to_header_field(f, pos1, pos2 - pos1);

        return 0;
    }

    pos1 = memchr(buf, ':', end_ptr - buf);
    if (pos1 == NULL)
        return http_error(HTTP_ERROR_GENERAL);

    long len1 = pos1 - buf;

    pos1++;
    str_trim_lws(&pos1, &pos2);
    long len2 = pos2 - pos1;

    char header_name[256];
    sprintf(header_name, "%.*s", (int) len1, buf);

    int field_num = list_size(hdr->fields);
    int found = http_get_header_field_num(hdr, header_name);
    if (!(flags & HTTP_MERGE_FIELDS) || found == -1) {
        if (http_add_header_field_len(hdr, buf, len1, pos1, len2 < 0 ? 0 : len2) != 0)
            return http_error(HTTP_ERROR_TOO_MANY_HEADER_FIELDS);
    } else {
        field_num = found;
        http_append_to_header_field(&hdr->fields[found], ", ", 2);
        http_append_to_header_field(&hdr->fields[found], pos1, len2);
    }

    hdr->last_field_num = field_num;
    return 0;
}

int http_parse_request(char *buf, http_req *req) {
    char *ptr, *pos0 = buf, *pos1, *pos2;
    long len;

    unsigned long header_len = strstr(buf, "\r\n\r\n") - buf + 4;
    if (header_len <= 0)
        return http_error(HTTP_ERROR_EOH_NOT_FOUND);

    for (int i = 0; i < header_len; i++) {
        if ((buf[i] >= 0x00 && buf[i] <= 0x1F && buf[i] != '\r' && buf[i] != '\n') || buf[i] == 0x7F)
            return http_error(HTTP_ERROR_HEADER_MALFORMED);
    }

    ptr = buf;
    while (header_len > (ptr - buf + 2)) {
        pos0 = strstr(ptr, "\r\n");
        if (pos0 == NULL)
            return http_error(HTTP_ERROR_HEADER_MALFORMED);

        if (req->version[0] == 0) {
            pos1 = (char *) strchr(ptr, ' ') + 1;
            if (pos1 == NULL)
                return http_error(HTTP_ERROR_HEADER_MALFORMED);

            if (pos1 - ptr - 1 >= sizeof(req->method))
                return http_error(HTTP_ERROR_HEADER_MALFORMED);

            for (int i = 0; i < (pos1 - ptr - 1); i++) {
                if (ptr[i] < 'A' || ptr[i] > 'Z')
                    return http_error(HTTP_ERROR_HEADER_MALFORMED);
            }
            snprintf(req->method, sizeof(req->method), "%.*s", (int) (pos1 - ptr - 1), ptr);

            pos2 = (char *) strchr(pos1, ' ') + 1;
            if (pos2 == NULL)
                return http_error(HTTP_ERROR_HEADER_MALFORMED);

            if (memcmp(pos2, "HTTP/", 5) != 0 || memcmp(pos2 + 8, "\r\n", 2) != 0)
                return http_error(HTTP_ERROR_INVALID_VERSION);

            len = pos2 - pos1 - 1;
            if (len >= 2048)
                return http_error(HTTP_ERROR_URI_TOO_LONG);

            req->uri = malloc(len + 1);
            sprintf(req->uri, "%.*s", (int) len, pos1);
            sprintf(req->version, "%.3s", pos2 + 5);
        } else {
            if (http_parse_header_field(&req->hdr, ptr, pos0, HTTP_MERGE_FIELDS) != 0)
                return -1;
        }
        ptr = pos0 + 2;
    }

    if (pos0[2] == '\r' && pos0[3] == '\n') {
        return (int) header_len;
    }

    return http_error(HTTP_ERROR_GENERAL);
}

int http_receive_request(sock *client, http_req *req) {
    long rcv_len;
    char buf[CLIENT_MAX_HEADER_SIZE];
    memset(buf, 0, sizeof(buf));
    memset(req->method, 0, sizeof(req->method));
    memset(req->version, 0, sizeof(req->version));
    req->uri = NULL;
    http_init_hdr(&req->hdr);

    rcv_len = sock_recv(client, buf, CLIENT_MAX_HEADER_SIZE - 1, MSG_PEEK);
    if (rcv_len <= 0)
        return -1;

    buf[rcv_len] = 0;

    long header_len = http_parse_request(buf, req);
    if (header_len < 0)
        return (int) -header_len;

    if (sock_recv_x(client, buf, header_len, 0) == -1)
        return -1;

    return 0;
}

const char *http_get_header_field(const http_hdr *hdr, const char *field_name) {
    int num = http_get_header_field_num(hdr, field_name);
    return (num >= 0 && num < list_size(hdr->fields)) ? http_field_get_value(&hdr->fields[num]) : NULL;
}

int http_get_header_field_num(const http_hdr *hdr, const char *field_name) {
    for (int i = 0; i < list_size(hdr->fields); i++) {
        if (strcasecmp(field_name, http_field_get_name(&hdr->fields[i])) == 0)
            return i;
    }

    return -1;
}

int http_add_header_field(http_hdr *hdr, const char *field_name, const char *field_value) {
    return http_add_header_field_len(hdr, field_name, strlen(field_name), field_value, strlen(field_value));
}

int http_add_header_field_len(http_hdr *hdr, const char *name, unsigned long name_len, const char *value, unsigned long value_len) {
    http_field *f;
    hdr->fields = list_append_ptr(hdr->fields, (void **) &f);

    if (name_len < sizeof(f->normal.name) && value_len < sizeof(f->normal.value)) {
        f->type = HTTP_FIELD_NORMAL;
        memcpy(f->normal.name, name, name_len);
        memcpy(f->normal.value, value, value_len);
        f->normal.name[name_len] = 0;
        f->normal.value[value_len] = 0;
        http_to_camel_case(f->normal.name, HTTP_PRESERVE);
    } else if (name_len < sizeof(f->ex_value.name)) {
        f->type = HTTP_FIELD_EX_VALUE;
        f->ex_value.value = malloc(value_len + 1);
        memcpy(f->ex_value.name, name, name_len);
        memcpy(f->ex_value.value, value, value_len);
        f->ex_value.name[name_len] = 0;
        f->ex_value.value[value_len] = 0;
        http_to_camel_case(f->ex_value.name, HTTP_PRESERVE);
    } else {
        f->type = HTTP_FIELD_EX_NAME;
        f->ex_name.name = malloc(name_len + 1);
        f->ex_name.value = malloc(value_len + 1);
        memcpy(f->ex_name.name, name, name_len);
        memcpy(f->ex_name.value, value, value_len);
        f->ex_name.name[name_len] = 0;
        f->ex_name.value[value_len] = 0;
        http_to_camel_case(f->ex_name.name, HTTP_PRESERVE);
    }

    return 0;
}

int http_add_to_header_field(http_hdr *hdr, const char *field_name, const char *field_value) {
    int field_num = http_get_header_field_num(hdr, field_name);
    if (field_num == -1)
        return http_add_header_field(hdr, field_name, field_value);

    http_append_to_header_field(&hdr->fields[field_num], field_value, strlen(field_value));
    return 0;
}

void http_append_to_header_field(http_field *field, const char *value, unsigned long len) {
    if (field->type == HTTP_FIELD_NORMAL) {
        unsigned long total_len = strlen(field->normal.value) + len + 1;
        if (total_len < sizeof(field->normal.value)) {
            strncat(field->normal.value, value, len);
        } else {
            field->type = HTTP_FIELD_EX_VALUE;
            char *new = malloc(total_len);
            strcpy(new, field->normal.value);
            strncat(new, value, len);
            field->ex_value.value = new;
        }
    } else if (field->type == HTTP_FIELD_EX_VALUE) {
        field->ex_value.value = realloc(field->ex_value.value, strlen(field->ex_value.value) + len + 1);
        strncat(field->ex_value.value, value, len);
    } else if (field->type == HTTP_FIELD_EX_NAME) {
        field->ex_name.value = realloc(field->ex_name.value, strlen(field->ex_name.value) + len + 1);
        strncat(field->ex_name.value, value, len);
    }
}

void http_remove_header_field(http_hdr *hdr, const char *field_name, int mode) {
    int i = 0;
    int diff = 1;
    if (mode == HTTP_REMOVE_LAST) {
        i = list_size(hdr->fields) - 1;
        diff = -1;
    }
    for (; i < list_size(hdr->fields) && i >= 0; i += diff) {
        if (strcasecmp(field_name, http_field_get_name(&hdr->fields[i])) == 0) {
            http_free_field(&hdr->fields[i]);
            list_remove(hdr->fields, i);
            if (mode == HTTP_REMOVE_ALL) {
                i -= diff;
            } else {
                return;
            }
        }
    }
}

int http_send_response(sock *client, http_res *res) {
    char buf[CLIENT_MAX_HEADER_SIZE];
    long off = sprintf(buf, "HTTP/%s %03i %s\r\n", res->version, res->status->code, res->status->msg);
    for (int i = 0; i < list_size(res->hdr.fields); i++) {
        const http_field *f = &res->hdr.fields[i];
        off += sprintf(buf + off, "%s: %s\r\n", http_field_get_name(f), http_field_get_value(f));
    }
    off += sprintf(buf + off, "\r\n");
    if (sock_send_x(client, buf, off, 0) != off)
        return -1;

    return 0;
}

int http_send_request(sock *server, http_req *req) {
    char buf[CLIENT_MAX_HEADER_SIZE];
    long off = sprintf(buf, "%s %s HTTP/%s\r\n", req->method, req->uri, req->version);
    for (int i = 0; i < list_size(req->hdr.fields); i++) {
        const http_field *f = &req->hdr.fields[i];
        off += sprintf(buf + off, "%s: %s\r\n", http_field_get_name(f), http_field_get_value(f));
    }
    off += sprintf(buf + off, "\r\n");
    if (sock_send_x(server, buf, off, 0) != off)
        return -1;

    return 0;
}

int http_send_100_continue(sock *client) {
    char buf[256];
    char date_buf[64];
    int size = sprintf(buf, "HTTP/1.1 100 Continue\r\nDate: %s\r\nServer: " SERVER_STR "\r\n\r\n",
                       http_get_date(date_buf, sizeof(date_buf)));
    return sock_send_x(client, buf, size, 0) == -1 ? -1 : 0;
}

const http_status *http_get_status(status_code_t status_code) {
    for (int i = 0; i < http_statuses_size; i++) {
        if (http_statuses[i].code == status_code) {
            return &http_statuses[i];
        }
    }
    return NULL;
}

const http_status_msg *http_get_error_msg(status_code_t status_code) {
    for (int i = 0; i < http_status_messages_size; i++) {
        if (http_status_messages[i].code == status_code) {
            return &http_status_messages[i];
        }
    }
    return NULL;
}

const char *http_get_status_color(status_code_t status_code) {
    if (status_code == 304) return HTTP_2XX_STR;
    switch (status_code / 100) {
        case 1: return HTTP_1XX_STR;
        case 2: return HTTP_2XX_STR;
        case 3: return HTTP_3XX_STR;
        case 4: return HTTP_4XX_STR;
        case 5: return HTTP_5XX_STR;
        default: return "";
    }
}

char *http_format_date(time_t ts, char *buf, size_t size) {
    struct tm time_info;
    strftime(buf, size, "%a, %d %b %Y %H:%M:%S GMT", gmtime_r(&ts, &time_info));
    return buf;
}

char *http_get_date(char *buf, size_t size) {
    time_t raw_time;
    time(&raw_time);
    return http_format_date(raw_time, buf, size);
}

const http_doc_info *http_get_status_info(status_code_t status_code) {
    static const http_doc_info info[] = {
            {"info",    HTTP_COLOR_INFO,    "/.sesimos/res/icon-info.svg",    http_info_doc},
            {"success", HTTP_COLOR_SUCCESS, "/.sesimos/res/icon-success.svg", http_success_doc},
            {"warning", HTTP_COLOR_WARNING, "/.sesimos/res/icon-warning.svg", http_warning_doc},
            {"error",   HTTP_COLOR_ERROR,   "/.sesimos/res/icon-error.svg",   http_error_doc}
    };
    if (status_code == 304) return &info[1];
    switch (status_code / 100) {
        case 1: return &info[0];
        case 2: return &info[1];
        case 3: return &info[2];
        case 4: // see case 5
        case 5: return &info[3];
        default: return NULL;
    }
}

int http_get_compression(const http_req *req, const http_res *res) {
    const char *accept_encoding = http_get_header_field(&req->hdr, "Accept-Encoding");
    const char *content_type = http_get_header_field(&res->hdr, "Content-Type");
    const char *content_encoding = http_get_header_field(&res->hdr, "Content-Encoding");
    if (mime_is_compressible(content_type) && content_encoding == NULL && accept_encoding != NULL) {
        if (strcontains(accept_encoding, "br")) {
            return COMPRESS_BR;
        } else if (strcontains(accept_encoding, "gzip")) {
            return COMPRESS_GZ;
        }
    }
    return 0;
}

long http_get_keep_alive_timeout(http_hdr *hdr) {
    const char *keep_alive = http_get_header_field(hdr, "Keep-Alive");
    if (!keep_alive) return -1;
    const char *timeout = strstr(keep_alive, "timeout=");
    if (!timeout) return -1;
    return strtol(timeout + 8, NULL, 10);
}
