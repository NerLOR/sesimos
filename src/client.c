/**
 * Necronda Web Server
 * Client connection and request handlers
 * src/client.c
 * Lorenz Stechauner, 2020-12-03
 */

#include "necronda-server.h"
#include "utils.h"
#include "uri.h"
#include "http.h"


int server_keep_alive = 1;
char *client_addr_str, *client_addr_str_ptr, *server_addr_str, *server_addr_str_ptr,
        *log_client_prefix, *log_conn_prefix, *log_req_prefix;

struct timeval client_timeout = {.tv_sec = CLIENT_TIMEOUT, .tv_usec = 0};

char *get_webroot(const char *http_host) {
    char *webroot = malloc(strlen(webroot_base) + strlen(http_host) + 1);
    unsigned long len = strlen(webroot_base);
    while (webroot_base[len - 1] == '/') len--;
    long pos = strchr(http_host, ':') - http_host;
    sprintf(webroot, "%.*s/%.*s", (int) len, webroot_base, (int) (pos == -1 ? strlen(http_host) : pos), http_host);
    return webroot;
}

void client_terminate() {
    server_keep_alive = 0;
}

int client_websocket_handler() {
    // TODO implement client_websocket_handler
    return 0;
}

int client_request_handler(sock *client, int req_num) {
    struct timespec begin, end;
    int ret, client_keep_alive, dir_mode;
    char buf0[1024], buf1[1024];
    char msg_buf[4096], msg_pre_buf[4096];
    char err_msg[256];
    err_msg[0] = 0;
    char *host, *hdr_connection, *webroot;
    unsigned long content_length = 0;

    http_res res;
    sprintf(res.version, "1.1");
    res.status = http_get_status(501);
    res.hdr.field_num = 0;
    http_add_header_field(&res.hdr, "Date", http_get_date(buf0, sizeof(buf0)));
    http_add_header_field(&res.hdr, "Server", SERVER_STR);

    clock_gettime(CLOCK_MONOTONIC, &begin);

    fd_set socket_fds;
    FD_ZERO(&socket_fds);
    FD_SET(client->socket, &socket_fds);
    client_timeout.tv_sec = CLIENT_TIMEOUT;
    client_timeout.tv_usec = 0;
    ret = select(client->socket + 1, &socket_fds, NULL, NULL, &client_timeout);
    if (ret <= 0) {
        if (errno != 0) {
            return 1;
        }
        client_keep_alive = 0;
        res.status = http_get_status(408);
        goto respond;
    }
    clock_gettime(CLOCK_MONOTONIC, &begin);

    http_req req;
    ret = http_receive_request(client, &req);
    if (ret != 0) {
        client_keep_alive = 0;
        if (ret < 0) {
            goto abort;
        } else if (ret == 1) {
            sprintf(err_msg, "Unable to parse header: Invalid header format.");
        } else if (ret == 2) {
            sprintf(err_msg, "Unable to parse header: Invalid method.");
        } else if (ret == 3) {
            sprintf(err_msg, "Unable to parse header: Invalid version");
        }
        res.status = http_get_status(400);
        goto respond;
    }

    hdr_connection = http_get_header_field(&req.hdr, "Connection", HTTP_LOWER);
    client_keep_alive = hdr_connection != NULL && strncmp(hdr_connection, "keep-alive", 10) == 0;
    host = http_get_header_field(&req.hdr, "Host", HTTP_LOWER);
    if (host == NULL || strchr(host, '/') != NULL) {
        res.status = http_get_status(400);
        sprintf(err_msg, "The client provided no or an invalid Host header field.");
        goto respond;
    }

    sprintf(log_req_prefix, "[%s%24s%s]%s ", BLD_STR, host, CLR_STR, log_client_prefix);
    log_prefix = log_req_prefix;
    print(BLD_STR "%s %s" CLR_STR, req.method, req.uri);

    webroot = get_webroot(host);
    if (webroot == NULL) {
        res.status = http_get_status(307);
        sprintf(buf0, "https://%s%s", NECRONDA_DEFAULT, req.uri);
        http_add_header_field(&req.hdr, "Location", buf0);
        goto respond;
    }

    dir_mode = URI_DIR_MODE_FORBIDDEN;
    http_uri uri;
    ret = uri_init(&uri, webroot, req.uri, dir_mode);
    if (ret != 0) {
        if (ret == 1) {
            sprintf(err_msg, "Invalid URI: has to start with slash.");
        } else if (ret == 2) {
            sprintf(err_msg, "Invalid URI: contains relative path change (/../).");
        }
        res.status = http_get_status(400);
        goto respond;
    }

    /*
    print("webroot:       %s", uri.webroot);
    print("req_path:      %s", uri.req_path);
    print("path:          %s", uri.path);
    print("pathinfo:      %s", uri.pathinfo);
    print("query:         %s", uri.query);
    print("filename:      %s", uri.filename);
    print("filename_comp: %s", uri.filename_comp);
    print("uri:           %s", uri.uri);
    print("is_static:     %i", uri.is_static);
    print("is_dir:        %i", uri.is_dir);
     */

    ssize_t size = sizeof(buf0);
    url_decode(req.uri, buf0, &size);
    if (strcmp(uri.uri, buf0) != 0 || (strncmp(uri.uri, "/.well-known/", 13) != 0 && !client->enc)) {
        res.status = http_get_status(308);
        size = sizeof(buf0);
        encode_url(uri.uri, buf0, &size);
        sprintf(buf1, "https://%s%s", host, buf0);
        http_add_header_field(&res.hdr, "Location", buf1);
        goto respond;
    }

    if (uri.filename == NULL && (int) uri.is_static && (int) uri.is_dir && strlen(uri.pathinfo) == 0) {
        res.status = http_get_status(403);
        sprintf(err_msg, "It is not allowed to list the contents of this directory.");
        goto respond;
    } else if (uri.filename == NULL && (int) !uri.is_static && (int) uri.is_dir && strlen(uri.pathinfo) == 0) {
        res.status = http_get_status(501);
        sprintf(err_msg, "Listing contents of an directory is currently not implemented.");
        // TODO list directory contents
        goto respond;
    } else if (uri.filename == NULL || (strlen(uri.pathinfo) > 0 && (int) uri.is_static)) {
        res.status = http_get_status(404);
        goto respond;
    }

    if ((int) uri.is_static && uri.filename != NULL) {
        uri_init_cache(&uri);
    }

    respond:
    if (server_keep_alive && client_keep_alive) {
        http_add_header_field(&res.hdr, "Connection", "keep-alive");
        sprintf(buf0, "timeout=%i, max=%i", CLIENT_TIMEOUT, REQ_PER_CONNECTION);
        http_add_header_field(&res.hdr, "Keep-Alive", buf0);
    } else {
        http_add_header_field(&res.hdr, "Connection", "close");
    }
    unsigned long len = 0;
    if (res.status->code >= 400 && res.status->code < 600) {
        http_error_msg *http_msg = http_get_error_msg(res.status->code);
        sprintf(msg_pre_buf, http_error_document, res.status->code, res.status->msg,
                http_msg != NULL ? http_msg->err_msg : "", err_msg[0] != 0 ? err_msg : "");
        len = sprintf(msg_buf, http_default_document, res.status->code, res.status->msg,
                      msg_pre_buf, res.status->code >= 300 && res.status->code < 400 ? "info" : "error",
                      http_error_icon, "#C00000");
        sprintf(buf0, "%li", len);
        http_add_header_field(&res.hdr, "Content-Length", buf0);
        http_add_header_field(&res.hdr, "Content-Type", "text/html; charset=UTF-8");
    } else {
        sprintf(buf0, "%li", content_length);
        http_add_header_field(&res.hdr, "Content-Length", buf0);
    }

    http_send_response(client, &res);
    if (res.status->code >= 400 && res.status->code < 600) {
        int snd_len = 0;
        while (snd_len < len) {
            if (client->enc) {
                ret = SSL_write(client->ssl, msg_buf, (int) (len - snd_len));
            } else {
                ret = send(client->socket, msg_buf, len - snd_len, 0);
            }
            snd_len += ret;
        }
    }

    clock_gettime(CLOCK_MONOTONIC, &end);
    char *location = http_get_header_field(&res.hdr, "Location", HTTP_PRESERVE_UPPER);
    unsigned long micros = (end.tv_nsec - begin.tv_nsec) / 1000 + (end.tv_sec - begin.tv_sec) * 1000000;
    print("%s%03i %s%s%s (%s)%s", http_get_status_color(res.status), res.status->code, res.status->msg,
          location != NULL ? " -> " : "", location != NULL ? location : "", format_duration(micros, buf0), CLR_STR);

    uri_free(&uri);
    abort:
    http_free_req(&req);
    http_free_res(&res);
    return !client_keep_alive;
}

int client_connection_handler(sock *client) {
    struct timespec begin, end;
    int ret, req_num;
    char buf[16];

    clock_gettime(CLOCK_MONOTONIC, &begin);
    print("Connection accepted from %s (%s) [%s]", client_addr_str, client_addr_str, "N/A");

    client_timeout.tv_sec = CLIENT_TIMEOUT;
    client_timeout.tv_usec = 0;
    if (setsockopt(client->socket, SOL_SOCKET, SO_RCVTIMEO, &client_timeout, sizeof(client_timeout)) < 0)
        goto set_timeout_err;
    if (setsockopt(client->socket, SOL_SOCKET, SO_SNDTIMEO, &client_timeout, sizeof(client_timeout)) < 0) {
        set_timeout_err:
        print(ERR_STR "Unable to set timeout for socket: %s" CLR_STR, strerror(errno));
        return 1;
    }

    if (client->enc) {
        client->ssl = SSL_new(client->ctx);
        SSL_set_fd(client->ssl, client->socket);
        SSL_set_accept_state(client->ssl);

        ret = SSL_accept(client->ssl);
        if (ret <= 0) {
            print(ERR_STR "Unable to perform handshake: %s" CLR_STR, ssl_get_error(client->ssl, ret));
            goto close;
        }
    }

    req_num = 0;
    ret = 0;
    while (ret == 0 && server_keep_alive && req_num < REQ_PER_CONNECTION) {
        ret = client_request_handler(client, req_num++);
        log_prefix = log_conn_prefix;
    }

    close:
    if (client->enc) {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    shutdown(client->socket, SHUT_RDWR);
    close(client->socket);

    clock_gettime(CLOCK_MONOTONIC, &end);
    unsigned long micros = (end.tv_nsec - begin.tv_nsec) / 1000 + (end.tv_sec - begin.tv_sec) * 1000000;

    print("Connection closed (%s)", format_duration(micros, buf));
    return 0;
}

int client_handler(sock *client, long client_num, struct sockaddr_in6 *client_addr) {
    int ret;
    struct sockaddr_in6 *server_addr;
    struct sockaddr_storage server_addr_storage;

    char *color_table[] = {"\x1B[31m", "\x1B[32m", "\x1B[33m", "\x1B[34m", "\x1B[35m", "\x1B[36m"};

    signal(SIGINT, client_terminate);
    signal(SIGTERM, client_terminate);

    client_addr_str_ptr = malloc(INET6_ADDRSTRLEN);
    inet_ntop(client_addr->sin6_family, (void *) &client_addr->sin6_addr, client_addr_str_ptr, INET6_ADDRSTRLEN);
    if (strncmp(client_addr_str_ptr, "::ffff:", 7) == 0) {
        client_addr_str = client_addr_str_ptr + 7;
    } else {
        client_addr_str = client_addr_str_ptr;
    }

    socklen_t len = sizeof(server_addr_storage);
    getsockname(client->socket, (struct sockaddr *) &server_addr_storage, &len);
    server_addr = (struct sockaddr_in6 *) &server_addr_storage;
    server_addr_str_ptr = malloc(INET6_ADDRSTRLEN);
    inet_ntop(server_addr->sin6_family, (void *) &server_addr->sin6_addr, server_addr_str_ptr, INET6_ADDRSTRLEN);
    if (strncmp(server_addr_str_ptr, "::ffff:", 7) == 0) {
        server_addr_str = server_addr_str_ptr + 7;
    } else {
        server_addr_str = server_addr_str_ptr;
    }

    log_req_prefix = malloc(256);
    log_client_prefix = malloc(256);
    sprintf(log_client_prefix, "[%s%4i%s]%s[%*s][%5i]%s", client->enc ? HTTPS_STR : HTTP_STR,
            ntohs(server_addr->sin6_port), CLR_STR, color_table[client_num % 6], INET_ADDRSTRLEN, client_addr_str,
            ntohs(client_addr->sin6_port), CLR_STR);

    log_conn_prefix = malloc(256);
    sprintf(log_conn_prefix, "[%24s]%s ", server_addr_str, log_client_prefix);
    log_prefix = log_conn_prefix;

    ret = client_connection_handler(client);
    free(client_addr_str_ptr);
    free(server_addr_str_ptr);
    free(log_conn_prefix);
    free(log_req_prefix);
    free(log_client_prefix);
    return ret;
}
