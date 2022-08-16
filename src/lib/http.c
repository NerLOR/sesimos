/**
 * Necronda Web Server
 * HTTP implementation
 * src/lib/http.c
 * Lorenz Stechauner, 2020-12-09
 */

#include "http.h"
#include "utils.h"
#include "compress.h"
#include <string.h>

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

void http_free_hdr(http_hdr *hdr) {
    for (int i = 0; i < hdr->field_num; i++) {
        http_field *f = &hdr->fields[i];
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
    hdr->field_num = 0;
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

int http_parse_header_field(http_hdr *hdr, const char *buf, const char *end_ptr) {
    if (hdr->last_field_num > hdr->field_num) {
        print(ERR_STR "Unable to parse header: Invalid state" CLR_STR);
        return 3;
    }

    char *pos1 = (char *) buf, *pos2 = (char *) end_ptr;
    if (buf[0] == ' ' || buf[0] == '\t') {
        if (hdr->last_field_num == -1) {
            print(ERR_STR "Unable to parse header" CLR_STR);
            return 3;
        }
        http_field *f = &hdr->fields[(int) hdr->last_field_num];

        str_trim_lws(&pos1, &pos2);
        http_append_to_header_field(f, pos1, pos2 - pos1);

        return 0;
    }

    pos1 = memchr(buf, ':', end_ptr - buf);
    if (pos1 == NULL) {
        print(ERR_STR "Unable to parse header" CLR_STR);
        return 3;
    }
    long len1 = pos1 - buf - 1;

    pos1++;
    str_trim_lws(&pos1, &pos2);
    long len2 = pos2 - pos1;

    char field_num = hdr->field_num;
    int found = http_get_header_field_num_len(hdr, buf, len1);
    if (found == -1) {
        if (http_add_header_field_len(hdr, buf, len1, pos1, len2 < 0 ? 0 : len2) != 0) {
            print(ERR_STR "Unable to parse header: Too many header fields" CLR_STR);
            return 3;
        }
    } else {
        field_num = (char) found;
        http_append_to_header_field(&hdr->fields[found], ", ", 2);
        http_append_to_header_field(&hdr->fields[found], pos1, len2);
    }

    hdr->last_field_num = (char) field_num;
    return 0;
}

int http_receive_request(sock *client, http_req *req) {
    long rcv_len, len;
    char buf[CLIENT_MAX_HEADER_SIZE];
    char *ptr, *pos0 = buf, *pos1, *pos2;
    memset(buf, 0, sizeof(buf));
    memset(req->method, 0, sizeof(req->method));
    memset(req->version, 0, sizeof(req->version));
    req->uri = NULL;
    req->hdr.field_num = 0;
    req->hdr.last_field_num = -1;

    while (1) {
        rcv_len  = sock_recv(client, buf, CLIENT_MAX_HEADER_SIZE, 0);
        if (rcv_len <= 0) {
            print("Unable to receive http header: %s", sock_strerror(client));
            return -1;
        }

        unsigned long header_len = strstr(buf, "\r\n\r\n") - buf + 4;
        if (header_len <= 0) {
            print(ERR_STR "Unable to parse http header: End of header not found" CLR_STR);
            return 5;
        }

        for (int i = 0; i < header_len; i++) {
            if ((buf[i] >= 0x00 && buf[i] <= 0x1F && buf[i] != '\r' && buf[i] != '\n') || buf[i] == 0x7F) {
                print(ERR_STR "Unable to parse http header: Header contains illegal characters" CLR_STR);
                return 4;
            }
        }

        ptr = buf;
        while (header_len > (ptr - buf + 2)) {
            pos0 = strstr(ptr, "\r\n");
            if (pos0 == NULL) {
                print(ERR_STR "Unable to parse http header: Invalid header format" CLR_STR);
                return 1;
            }

            if (req->version[0] == 0) {
                pos1 = memchr(ptr, ' ', rcv_len - (ptr - buf)) + 1;
                if (pos1 == NULL) goto err_hdr_fmt;

                if (pos1 - ptr - 1 >= sizeof(req->method)) {
                    print(ERR_STR "Unable to parse http header: Method name too long" CLR_STR);
                    return 2;
                }

                for (int i = 0; i < (pos1 - ptr - 1); i++) {
                    if (ptr[i] < 'A' || ptr[i] > 'Z') {
                        print(ERR_STR "Unable to parse http header: Invalid method" CLR_STR);
                        return 2;
                    }
                }
                snprintf(req->method, sizeof(req->method), "%.*s", (int) (pos1 - ptr - 1), ptr);

                pos2 = memchr(pos1, ' ', rcv_len - (pos1 - buf)) + 1;
                if (pos2 == NULL) {
                    err_hdr_fmt:
                    print(ERR_STR "Unable to parse http header: Invalid header format" CLR_STR);
                    return 1;
                }

                if (memcmp(pos2, "HTTP/", 5) != 0 || memcmp(pos2 + 8, "\r\n", 2) != 0) {
                    print(ERR_STR "Unable to parse http header: Invalid version" CLR_STR);
                    return 3;
                }

                len = pos2 - pos1 - 1;
                req->uri = malloc(len + 1);
                sprintf(req->uri, "%.*s", (int) len, pos1);
                sprintf(req->version, "%.3s", pos2 + 5);
            } else {
                int ret = http_parse_header_field(&req->hdr, ptr, pos0);
                if (ret != 0) return ret;
            }
            ptr = pos0 + 2;
        }
        if (pos0[2] == '\r' && pos0[3] == '\n') {
            break;
        }
    }

    client->buf_len = rcv_len - (pos0 - buf + 4);
    if (client->buf_len > 0) {
        client->buf = malloc(client->buf_len);
        client->buf_off = 0;
        memcpy(client->buf, pos0 + 4, client->buf_len);
    }

    return 0;
}

const char *http_get_header_field(const http_hdr *hdr, const char *field_name) {
    return http_get_header_field_len(hdr, field_name, strlen(field_name));
}

const char *http_get_header_field_len(const http_hdr *hdr, const char *field_name, unsigned long len) {
    return http_field_get_value(&hdr->fields[http_get_header_field_num_len(hdr, field_name, len)]);
}

int http_get_header_field_num(const http_hdr *hdr, const char *field_name) {
    return http_get_header_field_num_len(hdr, field_name, strlen(field_name));
}

int http_get_header_field_num_len(const http_hdr *hdr, const char *field_name, unsigned long len) {
    char field_name_1[256], field_name_2[256];
    memcpy(field_name_1, field_name, len);
    http_to_camel_case(field_name_1, HTTP_LOWER);
    for (int i = 0; i < hdr->field_num; i++) {
        strcpy(field_name_2, http_field_get_name(&hdr->fields[i]));
        http_to_camel_case(field_name_2, HTTP_LOWER);
        if (strcmp(field_name_1, field_name_2) == 0) {
            return i;
        }
    }
    return -1;
}

int http_add_header_field(http_hdr *hdr, const char *field_name, const char *field_value) {
    return http_add_header_field_len(hdr, field_name, strlen(field_name), field_value, strlen(field_value));
}

int http_add_header_field_len(http_hdr *hdr, const char *name, unsigned long name_len, const char *value, unsigned long value_len) {
    if (hdr->field_num >= HTTP_MAX_HEADER_FIELD_NUM)
        return -1;

    http_field *f = &hdr->fields[(int) hdr->field_num];

    if (name_len < sizeof(f->normal.name) && value_len < sizeof(f->normal.value)) {
        f->type = HTTP_FIELD_NORMAL;
        strncpy(f->normal.name, name, name_len);
        strncpy(f->normal.value, value, value_len);
        http_to_camel_case(f->normal.name, HTTP_PRESERVE);
    } else if (name_len < sizeof(f->ex_value.name)) {
        f->type = HTTP_FIELD_EX_VALUE;
        f->ex_value.value = malloc(value_len + 1);
        strncpy(f->ex_value.name, name, name_len);
        strncpy(f->ex_value.value, value, value_len);
        http_to_camel_case(f->ex_value.name, HTTP_PRESERVE);
    } else {
        f->type = HTTP_FIELD_EX_NAME;
        f->ex_name.name = malloc(name_len + 1);
        f->ex_name.value = malloc(value_len + 1);
        strncpy(f->ex_name.name, name, name_len);
        strncpy(f->ex_name.value, value, value_len);
        http_to_camel_case(f->ex_name.name, HTTP_PRESERVE);
    }

    hdr->field_num++;
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
    char field_name_1[256], field_name_2[256];
    strcpy(field_name_1, field_name);
    http_to_camel_case(field_name_1, HTTP_LOWER);

    int i = 0;
    int diff = 1;
    if (mode == HTTP_REMOVE_LAST) {
        i = hdr->field_num - 1;
        diff = -1;
    }
    for (; i < hdr->field_num && i >= 0; i += diff) {
        strcpy(field_name_2, http_field_get_name(&hdr->fields[i]));
        http_to_camel_case(field_name_2, HTTP_LOWER);
        if (strcmp(field_name_1, field_name_2) == 0) {
            memmove(&hdr->fields[i], &hdr->fields[i + 1], sizeof(hdr->fields[0]) * (hdr->field_num - i));
            hdr->field_num--;
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
    for (int i = 0; i < res->hdr.field_num; i++) {
        const http_field *f = &res->hdr.fields[i];
        off += sprintf(buf + off, "%s: %s\r\n", http_field_get_name(f), http_field_get_value(f));
    }
    off += sprintf(buf + off, "\r\n");
    if (sock_send(client, buf, off, 0) < 0) {
        return -1;
    }
    return 0;
}

int http_send_request(sock *server, http_req *req) {
    char buf[CLIENT_MAX_HEADER_SIZE];
    long off = sprintf(buf, "%s %s HTTP/%s\r\n", req->method, req->uri, req->version);
    for (int i = 0; i < req->hdr.field_num; i++) {
        const http_field *f = &req->hdr.fields[i];
        off += sprintf(buf + off, "%s: %s\r\n", http_field_get_name(f), http_field_get_value(f));
    }
    off += sprintf(buf + off, "\r\n");
    long ret = sock_send(server, buf, off, 0);
    if (ret <= 0) {
        return -1;
    }
    return 0;
}

const http_status *http_get_status(unsigned short status_code) {
    for (int i = 0; i < http_statuses_size / sizeof(http_status); i++) {
        if (http_statuses[i].code == status_code) {
            return &http_statuses[i];
        }
    }
    return NULL;
}

const http_status_msg *http_get_error_msg(const http_status *status) {
    unsigned short code = status->code;
    for (int i = 0; i < http_status_messages_size / sizeof(http_status_msg); i++) {
        if (http_status_messages[i].code == code) {
            return &http_status_messages[i];
        }
    }
    return NULL;
}

const char *http_get_status_color(const http_status *status) {
    unsigned short code = status->code;
    if (code >= 100 && code < 200) {
        return HTTP_1XX_STR;
    } else if ((code >= 200 && code < 300) || code == 304) {
        return HTTP_2XX_STR;
    } else if (code >= 300 && code < 400) {
        return HTTP_3XX_STR;
    } else if (code >= 400 && code < 500) {
        return HTTP_4XX_STR;
    } else if (code >= 500 && code < 600) {
        return HTTP_5XX_STR;
    }
    return "";
}

char *http_format_date(time_t time, char *buf, size_t size) {
    struct tm *timeinfo = gmtime(&time);
    strftime(buf, size, "%a, %d %b %Y %H:%M:%S GMT", timeinfo);
    return buf;
}

char *http_get_date(char *buf, size_t size) {
    time_t rawtime;
    time(&rawtime);
    return http_format_date(rawtime, buf, size);
}

const http_doc_info *http_get_status_info(const http_status *status) {
    unsigned short code = status->code;
    static http_doc_info info[] = {
            {"info", HTTP_COLOR_INFO, http_info_icon, http_info_document},
            {"success", HTTP_COLOR_SUCCESS, http_success_icon, http_success_document},
            {"warning", HTTP_COLOR_WARNING, http_warning_icon, http_warning_document},
            {"error", HTTP_COLOR_ERROR, http_error_icon, http_error_document}
    };
    if (code >= 100 && code < 200) {
        return &info[0];
    } else if ((code >= 200 && code < 300) || code == 304) {
        return &info[1];
    } else if (code >= 300 && code < 400) {
        return &info[2];
    } else if (code >= 400 && code < 600) {
        return &info[3];
    }
    return NULL;
}

int http_get_compression(const http_req *req, const http_res *res) {
    const char *accept_encoding = http_get_header_field(&req->hdr, "Accept-Encoding");
    const char *content_type = http_get_header_field(&res->hdr, "Content-Type");
    const char *content_encoding = http_get_header_field(&res->hdr, "Content-Encoding");
    if (mime_is_compressible(content_type) && content_encoding == NULL && accept_encoding != NULL) {
        if (strstr(accept_encoding, "br") != NULL) {
            return COMPRESS_BR;
        } else if (strstr(accept_encoding, "gzip") != NULL) {
            return COMPRESS_GZ;
        }
    }
    return 0;
}
