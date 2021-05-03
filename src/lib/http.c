/**
 * Necronda Web Server
 * HTTP implementation
 * src/lib/http.c
 * Lorenz Stechauner, 2020-12-09
 */

#include "http.h"
#include "utils.h"
#include "../necronda-server.h"
#include <string.h>

void http_to_camel_case(char *str, int mode) {
    char last = '-';
    char ch;
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

void http_free_hdr(http_hdr *hdr) {
    for (int i = 0; i < hdr->field_num; i++) {
        free(hdr->fields[i][0]);
        free(hdr->fields[i][1]);
    }
    hdr->field_num = 0;
}

void http_free_req(http_req *req) {
    if (req->uri == NULL) free(req->uri);
    req->uri = NULL;
    http_free_hdr(&req->hdr);
}

void http_free_res(http_res *res) {
    http_free_hdr(&res->hdr);
}

int http_parse_header_field(http_hdr *hdr, const char *buf, const char *end_ptr) {
    char *pos1 = memchr(buf, ':', end_ptr - buf);
    char *pos2;
    if (pos1 == NULL) {
        print(ERR_STR "Unable to parse header" CLR_STR);
        return 3;
    }

    long len = pos1 - buf;
    hdr->fields[(int) hdr->field_num][0] = malloc(len + 1);
    sprintf(hdr->fields[(int) hdr->field_num][0], "%.*s", (int) len, buf);
    http_to_camel_case(hdr->fields[(int) hdr->field_num][0], HTTP_CAMEL);

    pos1++;
    pos2 = (char *) end_ptr - 1;
    while (pos1[0] == ' ') pos1++;
    while (pos2[0] == ' ') pos2--;
    len = pos2 - pos1 + 1;

    if (len <= 0) {
        hdr->fields[(int) hdr->field_num][1] = malloc(1);
        hdr->fields[(int) hdr->field_num][1][0] = 0;
    } else {
        hdr->fields[(int) hdr->field_num][1] = malloc(len + 1);
        sprintf(hdr->fields[(int) hdr->field_num][1], "%.*s", (int) len, pos1);
    }
    hdr->field_num++;
    return 0;
}

int http_receive_request(sock *client, http_req *req) {
    long rcv_len, len;
    char *ptr, *pos0, *pos1, *pos2;
    char buf[CLIENT_MAX_HEADER_SIZE];
    memset(buf, 0, sizeof(buf));
    memset(req->method, 0, sizeof(req->method));
    memset(req->version, 0, sizeof(req->version));
    req->uri = NULL;
    req->hdr.field_num = 0;

    while (1) {
        rcv_len  = sock_recv(client, buf, CLIENT_MAX_HEADER_SIZE, 0);
        if (rcv_len <= 0) {
            print("Unable to receive: %s", sock_strerror(client));
            return -1;
        }

        unsigned long header_len = strstr(buf, "\r\n\r\n") - buf + 4;
        if (header_len <= 0) {
            print(ERR_STR "Unable to parse header: End of header not found" CLR_STR);
            return 5;
        }

        for (int i = 0; i < header_len; i++) {
            if ((buf[i] >= 0x00 && buf[i] <= 0x1F && buf[i] != '\r' && buf[i] != '\n') || buf[i] == 0x7F) {
                print(ERR_STR "Unable to parse header: Header contains illegal characters" CLR_STR);
                return 4;
            }
        }

        ptr = buf;
        while (header_len > (ptr - buf + 2)) {
            pos0 = strstr(ptr, "\r\n");
            if (pos0 == NULL) {
                print(ERR_STR "Unable to parse header: Invalid header format" CLR_STR);
                return 1;
            }

            if (req->version[0] == 0) {
                pos1 = memchr(ptr, ' ', rcv_len - (ptr - buf)) + 1;
                if (pos1 == NULL) goto err_hdr_fmt;

                if (pos1 - ptr - 1 >= sizeof(req->method)) {
                    print(ERR_STR "Unable to parse header: Method name too long" CLR_STR);
                    return 2;
                }

                for (int i = 0; i < (pos1 - ptr - 1); i++) {
                    if (ptr[i] < 'A' || ptr[i] > 'Z') {
                        print(ERR_STR "Unable to parse header: Invalid method" CLR_STR);
                        return 2;
                    }
                }
                strncpy(req->method, ptr, pos1 - ptr - 1);

                pos2 = memchr(pos1, ' ', rcv_len - (pos1 - buf)) + 1;
                if (pos2 == NULL) {
                    err_hdr_fmt:
                    print(ERR_STR "Unable to parse header: Invalid header format" CLR_STR);
                    return 1;
                }

                if (memcmp(pos2, "HTTP/", 5) != 0 || memcmp(pos2 + 8, "\r\n", 2) != 0) {
                    print(ERR_STR "Unable to parse header: Invalid version" CLR_STR);
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

char *http_get_header_field(const http_hdr *hdr, const char *field_name) {
    char field_name_1[256], field_name_2[256];
    strcpy(field_name_1, field_name);
    http_to_camel_case(field_name_1, HTTP_LOWER);
    for (int i = 0; i < hdr->field_num; i++) {
        strcpy(field_name_2, hdr->fields[i][0]);
        http_to_camel_case(field_name_2, HTTP_LOWER);
        if (strcmp(field_name_1, field_name_2) == 0) {
            return hdr->fields[i][1];
        }
    }
    return NULL;
}

void http_add_header_field(http_hdr *hdr, const char *field_name, const char *field_value) {
    size_t len_name = strlen(field_name);
    size_t len_value = strlen(field_value);
    char *_field_name = malloc(len_name + 1);
    char *_field_value = malloc(len_value + 1);
    strcpy(_field_name, field_name);
    strcpy(_field_value, field_value);
    http_to_camel_case(_field_name, HTTP_PRESERVE);
    hdr->fields[(int) hdr->field_num][0] = _field_name;
    hdr->fields[(int) hdr->field_num][1] = _field_value;
    hdr->field_num++;
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
        strcpy(field_name_2, hdr->fields[i][0]);
        http_to_camel_case(field_name_2, HTTP_LOWER);
        if (strcmp(field_name_1, field_name_2) == 0) {
            for (int j = i; j < hdr->field_num - 1; j++) {
                memcpy(hdr->fields[j], hdr->fields[j + 1], sizeof(hdr->fields[0]));
            }
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
        off += sprintf(buf + off, "%s: %s\r\n", res->hdr.fields[i][0], res->hdr.fields[i][1]);
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
        off += sprintf(buf + off, "%s: %s\r\n", req->hdr.fields[i][0], req->hdr.fields[i][1]);
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
