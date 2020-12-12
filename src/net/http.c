/**
 * Necronda Web Server
 * HTTP implementation
 * src/net/http.c
 * Lorenz Stechauner, 2020-12-09
 */

#include "http.h"
#include "utils.h"


void http_to_camel_case(char *str) {
    char last = '-';
    char ch;
    for (int i = 0; i < strlen(str); i++) {
        ch = str[i];
        if (last == '-' && ch >= 'a' && ch <= 'z') {
            str[i] = (char) ((int) ch & 0x5F);
        } else if (last != '-' && ch >= 'A' && ch <= 'Z') {
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
}

void http_free_req(http_req *req) {
    free(req->uri);
    http_free_hdr(&req->hdr);
}

int http_receive_request(sock *client, http_req *req) {
    ssize_t rcv_len, len;
    char *ptr, *pos0, *pos1, *pos2;
    char *buf = malloc(CLIENT_MAX_HEADER_SIZE);
    memset(buf, 0, sizeof(&buf));
    memset(req->method, 0, sizeof(req->method));
    memset(req->version, 0, sizeof(req->version));
    req->uri = NULL;
    req->hdr.field_num = 0;

    while (1) {
        if (client->enc) {
            rcv_len = SSL_read(client->ssl, buf, CLIENT_MAX_HEADER_SIZE);
            if (rcv_len < 0) {
                print(ERR_STR "Unable to receive: %s" CLR_STR, ssl_get_error(client->ssl, rcv_len));
                continue;
            }
        } else {
            rcv_len = recv(client->socket, buf, CLIENT_MAX_HEADER_SIZE, 0);
            if (rcv_len < 0) {
                print(ERR_STR "Unable to receive: %s" CLR_STR, strerror(errno));
                continue;
            }
        }

        ptr = buf;
        while (1) {
            pos0 = memchr(ptr, '\r', rcv_len - (ptr - buf));
            if (pos0 == NULL || pos0[1] != '\n') {
                print(ERR_STR "Unable to parse header: Invalid header format" CLR_STR);
                free(buf);
                return -1;
            } else if (pos0[2] == '\r' && pos0[3] == '\n') {
                free(buf);
                return 0;
            }

            if (ptr == buf) {
                if (memcmp(ptr, "GET ", 4) == 0) {
                    sprintf(req->method, "GET");
                } else if (memcmp(ptr, "HEAD ", 5) == 0) {
                    sprintf(req->method, "HEAD");
                } else if (memcmp(ptr, "POST ", 5) == 0) {
                    sprintf(req->method, "POST");
                } else if (memcmp(ptr, "PUT ", 4) == 0) {
                    sprintf(req->method, "PUT");
                } else if (memcmp(ptr, "DELETE ", 7) == 0) {
                    sprintf(req->method, "DELETE");
                } else if (memcmp(ptr, "CONNECT ", 7) == 0) {
                    sprintf(req->method, "CONNECT");
                } else if (memcmp(ptr, "OPTIONS ", 7) == 0) {
                    sprintf(req->method, "OPTIONS");
                } else if (memcmp(ptr, "TRACE ", 6) == 0) {
                    sprintf(req->method, "TRACE");
                } else {
                    print(ERR_STR "Unable to parse header: Invalid method" CLR_STR);
                    free(buf);
                    return -1;
                }

                pos1 = memchr(ptr, ' ', rcv_len - (ptr - buf)) + 1;
                if (pos1 == NULL) goto err_hdr_fmt;
                pos2 = memchr(pos1, ' ', rcv_len - (pos1 - buf)) + 1;
                if (pos2 == NULL) {
                    err_hdr_fmt:
                    print(ERR_STR "Unable to parse header: Invalid header format" CLR_STR);
                    free(buf);
                    return -1;
                }

                if (memcmp(pos2, "HTTP/", 5) != 0 || memcmp(pos2 + 8, "\r\n", 2) != 0) {
                    print(ERR_STR "Unable to parse header: Invalid version" CLR_STR);
                    free(buf);
                    return -1;
                }

                len = pos2 - pos1 - 1;
                req->uri = malloc(len + 1);
                sprintf(req->uri, "%.*s", (int) len, pos1);
                sprintf(req->version, "%.3s", pos2 + 5);
            } else {
                pos1 = memchr(ptr, ':', pos0 - ptr);
                if (pos1 == NULL) {
                    print(ERR_STR "Unable to parse header: Invalid version" CLR_STR);
                    free(buf);
                    return -1;
                }

                len = pos1 - ptr;
                req->hdr.fields[req->hdr.field_num][0] = malloc(len + 1);
                sprintf(req->hdr.fields[req->hdr.field_num][0], "%.*s", (int) len, ptr);
                http_to_camel_case(req->hdr.fields[req->hdr.field_num][0]);

                pos1++;
                pos2 = pos0 - 1;
                while (pos1[0] == ' ') pos1++;
                while (pos2[0] == ' ') pos2--;
                len = pos2 - pos1 + 1;
                req->hdr.fields[req->hdr.field_num][1] = malloc(len + 1);
                sprintf(req->hdr.fields[req->hdr.field_num][1], "%.*s", (int) len, pos1);

                req->hdr.field_num++;
            }

            ptr = pos0 + 2;
        }
    }
}

char *http_get_header_field(http_hdr *hdr, const char *field_name) {
    size_t len = strlen(field_name);
    char *_field_name = malloc(len + 1);
    sprintf(_field_name, "%s", field_name);
    http_to_camel_case(_field_name);
    for (int i = 0; i < hdr->field_num; i++) {
        if (strncmp(hdr->fields[i][0], _field_name, len) == 0) {
            return hdr->fields[i][1];
        }
    }
    return NULL;
}
