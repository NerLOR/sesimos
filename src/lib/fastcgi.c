/**
 * sesimos - secure, simple, modern web server
 * @brief FastCGI interface implementation
 * @file src/lib/fastcgi.c
 * @author Lorenz Stechauner
 * @date 2020-12-26
 */

#include "../defs.h"
#include "fastcgi.h"
#include "utils.h"
#include "../logger.h"
#include "list.h"

#include <sys/un.h>
#include <sys/socket.h>
#include <string.h>

// TODO use pipes for stdin, stdout, stderr in FastCGI

char *fastcgi_add_param(char *buf, const char *key, const char *value) {
    char *ptr = buf;
    unsigned long key_len = strlen(key);
    unsigned long val_len = strlen(value);

    if (key_len <= 127) {
        ptr[0] = (char) (key_len & 0x7F);
        ptr++;
    } else {
        *((int *) ptr) = htonl(0x80000000 | key_len);
        ptr += 4;
    }
    if (val_len <= 127) {
        ptr[0] = (char) (val_len & 0x7F);
        ptr++;
    } else {
        *((int *) ptr) = htonl(0x80000000 | val_len);
        ptr += 4;
    }

    memcpy(ptr, key, key_len);
    ptr += key_len;
    memcpy(ptr, value, val_len);
    ptr += val_len;

    return ptr;
}

int fastcgi_send_data(fastcgi_cnx_t *cnx, unsigned char type, unsigned short len, void *data) {
    // build header
    FCGI_Header header = {
            .version = FCGI_VERSION_1,
            .type = type,
            .requestId = htons(cnx->req_id),
            .contentLength = htons(len),
            .paddingLength = 0,
            .reserved = 0,
    };

    // send FastCGI header with MSG_MORE flag
    if (sock_send_x(&cnx->socket, &header, sizeof(header), (len != 0) ? MSG_MORE : 0) == -1) {
        error("Unable to send to FastCGI socket");
        return -1;
    }

    // send data (if available)
    if (sock_send_x(&cnx->socket, data, len, 0) == -1) {
        error("Unable to send to FastCGI socket");
        return -1;
    }

    // return bytes sent totally
    return len + (int) sizeof(header);
}

int fastcgi_init(fastcgi_cnx_t *conn, int mode, unsigned int req_num, const sock *client, const http_req *req, const http_uri *uri) {
    conn->mode = mode;
    conn->req_id = (req_num + 1) & 0xFFFF;
    conn->out_buf = NULL;
    conn->out_off = 0;
    conn->webroot = uri->webroot;

    conn->socket.enc = 0;
    if ((conn->socket.socket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        error("Unable to create unix socket");
        return -1;
    }

    struct sockaddr_un sock_addr = { AF_UNIX };
    if (conn->mode == FASTCGI_BACKEND_PHP) {
        strcpy(sock_addr.sun_path, PHP_FPM_SOCKET);
    }

    if (connect(conn->socket.socket, (struct sockaddr *) &sock_addr, sizeof(sock_addr)) != 0) {
        error("Unable to connect to unix socket of FastCGI socket");
        return -1;
    }

    FCGI_BeginRequestBody begin = {
            .role = htons(FCGI_RESPONDER),
            .flags = 0,
            .reserved = {0},
    };

    if (fastcgi_send_data(conn, FCGI_BEGIN_REQUEST, sizeof(begin), &begin) == -1)
        return -1;

    char param_buf[4096], buf0[256], *param_ptr = param_buf;
    param_ptr = fastcgi_add_param(param_ptr, "REDIRECT_STATUS", "CGI");
    param_ptr = fastcgi_add_param(param_ptr, "DOCUMENT_ROOT", uri->webroot);
    param_ptr = fastcgi_add_param(param_ptr, "GATEWAY_INTERFACE", "CGI/1.1");
    param_ptr = fastcgi_add_param(param_ptr, "SERVER_SOFTWARE", SERVER_STR);
    param_ptr = fastcgi_add_param(param_ptr, "SERVER_PROTOCOL", "HTTP/1.1");
    param_ptr = fastcgi_add_param(param_ptr, "SERVER_NAME", http_get_header_field(&req->hdr, "Host"));
    if (client->enc) {
        param_ptr = fastcgi_add_param(param_ptr, "HTTPS", "on");
    }

    struct sockaddr_storage addr_storage;
    struct sockaddr_in6 *addr;
    socklen_t len = sizeof(addr_storage);
    getsockname(client->socket, (struct sockaddr *) &addr_storage, &len);
    addr = (struct sockaddr_in6 *) &addr_storage;
    sprintf(buf0, "%i", ntohs(addr->sin6_port));
    param_ptr = fastcgi_add_param(param_ptr, "SERVER_PORT", buf0);

    len = sizeof(addr_storage);
    getpeername(client->socket, (struct sockaddr *) &addr_storage, &len);
    addr = (struct sockaddr_in6 *) &addr_storage;
    sprintf(buf0, "%i", ntohs(addr->sin6_port));
    param_ptr = fastcgi_add_param(param_ptr, "REMOTE_PORT", buf0);
    param_ptr = fastcgi_add_param(param_ptr, "REMOTE_ADDR", conn->r_addr);
    param_ptr = fastcgi_add_param(param_ptr, "REMOTE_HOST", conn->r_host != NULL ? conn->r_host : conn->r_addr);
    //param_ptr = fastcgi_add_param(param_ptr, "REMOTE_IDENT", "");
    //param_ptr = fastcgi_add_param(param_ptr, "REMOTE_USER", "");

    param_ptr = fastcgi_add_param(param_ptr, "REQUEST_METHOD", req->method);
    param_ptr = fastcgi_add_param(param_ptr, "REQUEST_URI", req->uri);
    param_ptr = fastcgi_add_param(param_ptr, "SCRIPT_NAME", uri->filename + strlen(uri->webroot));
    param_ptr = fastcgi_add_param(param_ptr, "SCRIPT_FILENAME", uri->filename);
    //param_ptr = fastcgi_add_param(param_ptr, "PATH_TRANSLATED", uri->filename);

    param_ptr = fastcgi_add_param(param_ptr, "QUERY_STRING", uri->query != NULL ? uri->query : "");
    if (uri->pathinfo != NULL && strlen(uri->pathinfo) > 0) {
        sprintf(buf0, "/%s", uri->pathinfo);
    } else {
        buf0[0] = 0;
    }
    param_ptr = fastcgi_add_param(param_ptr, "PATH_INFO", buf0);

    //param_ptr = fastcgi_add_param(param_ptr, "AUTH_TYPE", "");
    const char *content_length = http_get_header_field(&req->hdr, "Content-Length");
    param_ptr = fastcgi_add_param(param_ptr, "CONTENT_LENGTH", content_length != NULL ? content_length : "");
    const char *content_type = http_get_header_field(&req->hdr, "Content-Type");
    param_ptr = fastcgi_add_param(param_ptr, "CONTENT_TYPE", content_type != NULL ? content_type : "");
    //if (conn->ctx->geoip[0] != 0) {
    //    param_ptr = fastcgi_add_param(param_ptr, "REMOTE_INFO", conn->ctx->geoip);
    //}

    for (int i = 0; i < list_size(req->hdr.fields); i++) {
        const http_field *f = &req->hdr.fields[i];
        const char *name = http_field_get_name(f);
        char *ptr = buf0;
        ptr += sprintf(ptr, "HTTP_");
        for (int j = 0; j < strlen(name); j++, ptr++) {
            char ch = name[j];
            if ((ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9')) {
                ch = ch;
            } else if (ch >= 'a' && ch <= 'z') {
                ch &= 0x5F;
            } else {
                ch = '_';
            }
            ptr[0] = ch;
            ptr[1] = 0;
        }
        param_ptr = fastcgi_add_param(param_ptr, buf0, http_field_get_value(f));
    }

    if (fastcgi_send_data(conn, FCGI_PARAMS, param_ptr - param_buf, param_buf) == -1)
        return -1;

    if (fastcgi_send_data(conn, FCGI_PARAMS, 0, NULL) == -1)
        return -1;

    return 0;
}

int fastcgi_close_stdin(fastcgi_cnx_t *conn) {
    if (fastcgi_send_data(conn, FCGI_STDIN, 0, NULL) == -1)
        return -1;

    return 0;
}

int fastcgi_php_error(const fastcgi_cnx_t *conn, const char *msg, int msg_len, char *err_msg) {
    char *msg_str = malloc(msg_len + 1);
    char *ptr0 = msg_str;
    memcpy(msg_str, msg, msg_len);
    msg_str[msg_len] = 0;
    char *ptr1 = NULL;
    int len, err = 0;

    // FIXME *msg is part of a stream, handle fragmented lines
    while (1) {
        log_lvl_t msg_type = LOG_INFO;
        int msg_pre_len = 0;
        ptr1 = strstr(ptr0, "PHP message: ");
        if (ptr1 == NULL) {
            len = (int) (msg_len - (ptr0 - msg_str));
            if (ptr0 == msg_str) msg_type = 2;
        } else {
            len = (int) (ptr1 - ptr0);
        }
        if (len == 0) {
            goto next;
        }

        if (len >= 14 && strstarts(ptr0, "PHP Warning:  ")) {
            msg_type = LOG_WARNING;
            msg_pre_len = 14;
        } else if (len >= 18 && strstarts(ptr0, "PHP Fatal error:  ")) {
            msg_type = LOG_ERROR;
            msg_pre_len = 18;
        } else if (len >= 18 && strstarts(ptr0, "PHP Parse error:  ")) {
            msg_type = LOG_ERROR;
            msg_pre_len = 18;
        } else if (len >= 18 && strstarts(ptr0, "PHP Notice:  ")) {
            msg_type = LOG_NOTICE;
            msg_pre_len = 13;
        }

        char *ptr2 = ptr0;
        char *ptr3;
        int len2;
        while (ptr2 - ptr0 < len) {
            ptr3 = strchr(ptr2, '\n');
            len2 = (int) (len - (ptr2 - ptr0));
            if (ptr3 != NULL && (ptr3 - ptr2) < len2) {
                len2 = (int) (ptr3 - ptr2);
            }
            logmsgf(msg_type, "%.*s", len2, ptr2);
            if (msg_type == 2 && ptr2 == ptr0) {
                strcpy_rem_webroot(err_msg, ptr2, len2, conn->webroot);
                err = 1;
            }
            if (ptr3 == NULL) {
                break;
            }
            ptr2 = ptr3 + 1;
        }

        next:
        if (ptr1 == NULL) {
            break;
        }
        ptr0 = ptr1 + 13;
    }
    free(msg_str);
    return err;
}

int fastcgi_header(fastcgi_cnx_t *conn, http_res *res, char *err_msg) {
    FCGI_Header header;
    char *content;
    unsigned short content_len, req_id;
    long ret;
    int err = 0;

    while (1) {
        if (sock_recv_x(&conn->socket, &header, sizeof(header), 0) == -1) {
            res->status = http_get_status(500);
            sprintf(err_msg, "Unable to communicate with FastCGI socket.");
            error("Unable to receive from FastCGI socket");
            return 1;
        }
        req_id = ntohs(header.requestId);
        content_len = ntohs(header.contentLength);
        content = malloc(content_len + header.paddingLength);
        if (sock_recv_x(&conn->socket, content, content_len + header.paddingLength, 0) == -1) {
            res->status = http_get_status(500);
            sprintf(err_msg, "Unable to communicate with FastCGI socket.");
            error("Unable to receive from FastCGI socket");
            free(content);
            return 1;
        }

        if (req_id != conn->req_id) {
            continue;
        }

        if (header.type == FCGI_END_REQUEST) {
            FCGI_EndRequestBody *body = (FCGI_EndRequestBody *) content;
            int app_status = ntohl(body->appStatus);
            if (body->protocolStatus != FCGI_REQUEST_COMPLETE) {
                error("FastCGI protocol error: %i", body->protocolStatus);
            }
            if (app_status != 0) {
                error("FastCGI app terminated with exit code %i", app_status);
            }
            sock_close(&conn->socket);
            free(content);
            return 1;
        } else if (header.type == FCGI_STDERR) {
            if (conn->mode == FASTCGI_BACKEND_PHP) {
                err = err || fastcgi_php_error(conn, content, content_len, err_msg);
            }
        } else if (header.type == FCGI_STDOUT) {
            break;
        } else {
            error("Unknown FastCGI type: %i", header.type);
        }

        free(content);
    }
    if (err) {
        res->status = http_get_status(500);
        return 2;
    }

    conn->out_buf = content;
    conn->out_len = content_len;
    conn->out_off = (unsigned short) (strstr(content, "\r\n\r\n") - content + 4);

    char *buf = content;
    unsigned short header_len = conn->out_off;
    if (header_len <= 0) {
        error("Unable to parse header: End of header not found");
        return 1;
    }

    for (int i = 0; i < header_len; i++) {
        if ((buf[i] >= 0x00 && buf[i] <= 0x1F && buf[i] != '\r' && buf[i] != '\n') || buf[i] == 0x7F) {
            error("Unable to parse header: Header contains illegal characters");
            return 2;
        }
    }

    char *ptr = buf;
    while (header_len != (ptr - buf)) {
        char *pos0 = strstr(ptr, "\r\n");
        if (pos0 == NULL) {
            error("Unable to parse header: Invalid header format");
            return 1;
        }

        ret = http_parse_header_field(&res->hdr, ptr, pos0, 0);
        if (ret != 0) return (int) ret;

        if (pos0[2] == '\r' && pos0[3] == '\n') {
            return 0;
        }
        ptr = pos0 + 2;
    }

    return 0;
}

int fastcgi_send(fastcgi_cnx_t *conn, sock *client, int flags) {
    FCGI_Header header;
    long ret;
    char buf0[256], *content, *ptr;
    int len;
    unsigned short content_len;

    if (conn->out_buf != NULL && conn->out_len > conn->out_off) {
        content = conn->out_buf;
        ptr = content + conn->out_off;
        content_len = conn->out_len - conn->out_off;
        goto out;
    }

    while (1) {
        if ((sock_recv_x(&conn->socket, &header, sizeof(header), 0)) == -1) {
            error("Unable to receive from FastCGI socket");
            return -1;
        }

        content_len = ntohs(header.contentLength);
        content = malloc(content_len + header.paddingLength);
        ptr = content;

        long rcv_len = 0;
        while (rcv_len < content_len + header.paddingLength) {
            ret = sock_recv(&conn->socket, content + rcv_len, content_len + header.paddingLength - rcv_len, 0);
            if (ret < 0) {
                error("Unable to receive from FastCGI socket");
                free(content);
                return -1;
            }
            rcv_len += ret;
        }

        if (header.type == FCGI_END_REQUEST) {
            FCGI_EndRequestBody *body = (FCGI_EndRequestBody *) content;
            int app_status = ntohl(body->appStatus);
            if (body->protocolStatus != FCGI_REQUEST_COMPLETE) {
                error("FastCGI protocol error: %i", body->protocolStatus);
            }
            if (app_status != 0) {
                error("FastCGI app terminated with exit code %i", app_status);
            }
            sock_close(&conn->socket);
            free(content);

            if (flags & FASTCGI_CHUNKED) {
                sock_send_x(client, "0\r\n\r\n", 5, 0);
            }

            return 0;
        } else if (header.type == FCGI_STDERR) {
            if (conn->mode == FASTCGI_BACKEND_PHP) {
                fastcgi_php_error(conn, content, content_len, buf0);
            }
        } else if (header.type == FCGI_STDOUT) {
            out:
            if (content_len != 0) {
                len = sprintf(buf0, "%X\r\n", content_len);
                if (flags & FASTCGI_CHUNKED) sock_send_x(client, buf0, len, 0);
                sock_send_x(client, ptr, content_len, 0);
                if (flags & FASTCGI_CHUNKED) sock_send_x(client, "\r\n", 2, 0);
            }
        } else {
            error("Unknown FastCGI type: %i", header.type);
        }
        free(content);
    }
}

int fastcgi_dump(fastcgi_cnx_t *conn, char *buf, long len) {
    FCGI_Header header;
    long ret;
    char buf0[256];
    char *content, *ptr = buf;
    unsigned short content_len;

    if (conn->out_buf != NULL && conn->out_len > conn->out_off) {
        ptr += snprintf(ptr, len, "%.*s", conn->out_len - conn->out_off, conn->out_buf + conn->out_off);
    }

    while (1) {
        if (sock_recv_x(&conn->socket, &header, sizeof(header), 0) == -1) {
            error("Unable to receive from FastCGI socket");
            return -1;
        }

        content_len = ntohs(header.contentLength);
        content = malloc(content_len + header.paddingLength);

        long rcv_len = 0;
        while (rcv_len < content_len + header.paddingLength) {
            ret = sock_recv(&conn->socket, content + rcv_len, content_len + header.paddingLength - rcv_len, 0);
            if (ret < 0) {
                error("Unable to receive from FastCGI socket");
                free(content);
                return -1;
            }
            rcv_len += ret;
        }

        if (header.type == FCGI_END_REQUEST) {
            FCGI_EndRequestBody *body = (FCGI_EndRequestBody *) content;
            int app_status = ntohl(body->appStatus);
            if (body->protocolStatus != FCGI_REQUEST_COMPLETE) {
                error("FastCGI protocol error: %i", body->protocolStatus);
            }
            if (app_status != 0) {
                error("FastCGI app terminated with exit code %i", app_status);
            }
            sock_close(&conn->socket);
            free(content);

            return 0;
        } else if (header.type == FCGI_STDERR) {
            if (conn->mode == FASTCGI_BACKEND_PHP) {
                fastcgi_php_error(conn, content, content_len, buf0);
            }
        } else if (header.type == FCGI_STDOUT) {
            ptr += snprintf(ptr, len - (ptr - buf), "%.*s", content_len, content);
        } else {
            error("Unknown FastCGI type: %i", header.type);
        }
        free(content);
    }
}

int fastcgi_receive(fastcgi_cnx_t *conn, sock *client, unsigned long len) {
    char *buf[16384];

    for (long to_send = (long) len, ret; to_send > 0; to_send -= ret) {
        if ((ret = sock_recv(client, buf, (to_send > sizeof(buf)) ? sizeof(buf) : to_send, 0)) <= 0) {
            error("Unable to receive");
            return -1;
        }

        if (fastcgi_send_data(conn, FCGI_STDIN, ret, buf) == -1)
            return -1;
    }

    return 0;
}

int fastcgi_receive_chunked(fastcgi_cnx_t *conn, sock *client) {
    for (long ret;;) {
        if ((ret = sock_get_chunk_header(client)) < 0) {
            return (int) ret;
        } else if (ret == 0) {
            break;
        }

        if ((ret = fastcgi_receive(conn, client, ret)) < 0)
            return (int) ret;
    }

    return 0;
}
