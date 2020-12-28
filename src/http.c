/**
 * Necronda Web Server
 * HTTP implementation
 * src/net/http.c
 * Lorenz Stechauner, 2020-12-09
 */

#include "http.h"
#include "utils.h"


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
        print(ERR_STR "Unable to parse header: Invalid version" CLR_STR);
        return 3;
    }

    unsigned long len = pos1 - buf;
    hdr->fields[hdr->field_num][0] = malloc(len + 1);
    sprintf(hdr->fields[hdr->field_num][0], "%.*s", (int) len, buf);
    http_to_camel_case(hdr->fields[hdr->field_num][0], HTTP_CAMEL);

    pos1++;
    pos2 = (char *) end_ptr - 1;
    while (pos1[0] == ' ') pos1++;
    while (pos2[0] == ' ') pos2--;
    len = pos2 - pos1 + 1;
    hdr->fields[hdr->field_num][1] = malloc(len + 1);
    sprintf(hdr->fields[hdr->field_num][1], "%.*s", (int) len, pos1);
    hdr->field_num++;

    return 0;
}

int http_receive_request(sock *client, http_req *req) {
    unsigned long rcv_len, len;
    char *ptr, *pos0, *pos1, *pos2;
    char buf[CLIENT_MAX_HEADER_SIZE];
    memset(buf, 0, sizeof(buf));
    memset(req->method, 0, sizeof(req->method));
    memset(req->version, 0, sizeof(req->version));
    req->uri = NULL;
    req->hdr.field_num = 0;

    while (1) {
        if (client->enc) {
            rcv_len = SSL_read(client->ssl, buf, CLIENT_MAX_HEADER_SIZE);
            if (rcv_len < 0) {
                print(ERR_STR "Unable to receive: %s" CLR_STR, ssl_get_error(client->ssl, rcv_len));
                return -1;
            }
        } else {
            rcv_len = recv(client->socket, buf, CLIENT_MAX_HEADER_SIZE, 0);
            if (rcv_len < 0) {
                print(ERR_STR "Unable to receive: %s" CLR_STR, strerror(errno));
                return -1;
            }
        }

        if (rcv_len == 0) {
            print("Unable to receive: closed");
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
        while (header_len != (ptr - buf)) {
            pos0 = strstr(ptr, "\r\n");
            if (pos0 == NULL) {
                print(ERR_STR "Unable to parse header: Invalid header format" CLR_STR);
                return 1;
            }

            if (req->version[0] == 0) {
                if (memcmp(ptr, "GET ", 4) == 0) {
                    strcpy(req->method, "GET");
                } else if (memcmp(ptr, "HEAD ", 5) == 0) {
                    strcpy(req->method, "HEAD");
                } else if (memcmp(ptr, "POST ", 5) == 0) {
                    strcpy(req->method, "POST");
                } else if (memcmp(ptr, "PUT ", 4) == 0) {
                    strcpy(req->method, "PUT");
                } else if (memcmp(ptr, "DELETE ", 7) == 0) {
                    strcpy(req->method, "DELETE");
                } else if (memcmp(ptr, "CONNECT ", 7) == 0) {
                    strcpy(req->method, "CONNECT");
                } else if (memcmp(ptr, "OPTIONS ", 7) == 0) {
                    strcpy(req->method, "OPTIONS");
                } else if (memcmp(ptr, "TRACE ", 6) == 0) {
                    strcpy(req->method, "TRACE");
                } else {
                    print(ERR_STR "Unable to parse header: Invalid method" CLR_STR);
                    return 2;
                }

                pos1 = memchr(ptr, ' ', rcv_len - (ptr - buf)) + 1;
                if (pos1 == NULL) goto err_hdr_fmt;
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
            if (pos0[2] == '\r' && pos0[3] == '\n') {
                return 0;
            }
            ptr = pos0 + 2;
        }
    }
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
    hdr->fields[hdr->field_num][0] = _field_name;
    hdr->fields[hdr->field_num][1] = _field_value;
    hdr->field_num++;
}

void http_remove_header_field(http_hdr *hdr, const char *field_name, int mode) {
    char field_name_1[256], field_name_2[256];
    strcpy(field_name_1, field_name);
    http_to_camel_case(field_name_1, HTTP_LOWER);
    for (int i = 0; i < hdr->field_num; i++) {
        strcpy(field_name_2, hdr->fields[i][0]);
        http_to_camel_case(field_name_2, HTTP_LOWER);
        if (strcmp(field_name_1, field_name_2) == 0) {
            for (int j = i; j < hdr->field_num - 1; j++) {
                memcpy(hdr->fields[j], hdr->fields[j + 1], sizeof(hdr->fields[0]));
            }
            hdr->field_num--;
            if (mode == HTTP_REMOVE_ONE) {
                return;
            } else if (mode == HTTP_REMOVE_ALL) {
                i--;
            }
        }
    }
}

int http_send_response(sock *client, http_res *res) {
    char buf[CLIENT_MAX_HEADER_SIZE];
    int len = 0;
    int snd_len = 0;

    len += sprintf(buf + len, "HTTP/%s %03i %s\r\n", res->version, res->status->code, res->status->msg);
    for (int i = 0; i < res->hdr.field_num; i++) {
        len += sprintf(buf + len, "%s: %s\r\n", res->hdr.fields[i][0], res->hdr.fields[i][1]);
    }
    len += sprintf(buf + len, "\r\n");

    if (client->enc) {
        snd_len = SSL_write(client->ssl, buf, len);
    } else {
        snd_len = send(client->socket, buf, len, 0);
    }

    return 0;
}

http_status *http_get_status(unsigned short status_code) {
    for (int i = 0; i < sizeof(http_statuses) / sizeof(http_status); i++) {
        if (http_statuses[i].code == status_code) {
            return &http_statuses[i];
        }
    }
    return NULL;
}

http_error_msg *http_get_error_msg(unsigned short status_code) {
    for (int i = 0; i < sizeof(http_error_messages) / sizeof(http_get_error_msg); i++) {
        if (http_error_messages[i].code == status_code) {
            return &http_error_messages[i];
        }
    }
    return NULL;
}

const char *http_get_status_color(http_status *status) {
    unsigned short code = status->code;
    if (code >= 100 && code < 200) {
        return HTTP_1XX_STR;
    } else if (code >= 200 && code < 300 || code == 304) {
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
