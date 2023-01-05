/**
 * Sesimos - secure, simple, modern web server
 * @brief Main executable
 * @file src/server.c
 * @author Lorenz Stechauner
 * @date 2020-12-03
 */

#include "defs.h"
#include "server.h"
#include "logger.h"
#include "async.h"

#include "cache_handler.h"
#include "lib/config.h"
#include "lib/proxy.h"
#include "lib/geoip.h"
#include "workers.h"
#include "worker/func.h"
#include "lib/list.h"

#include <stdio.h>
#include <getopt.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>


const char *config_file;

static int sockets[NUM_SOCKETS];
static SSL_CTX *contexts[CONFIG_MAX_CERT_CONFIG];

static client_ctx_t **clients;

static const char *color_table[] = {"\x1B[31m", "\x1B[32m", "\x1B[33m", "\x1B[34m", "\x1B[35m", "\x1B[36m"};

static int clean() {
    remove("/var/sesimos/server/cache");
    rmdir("/var/sesimos/server/");
    return 0;
}

static int ssl_servername_cb(SSL *ssl, int *ad, void *arg) {
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername != NULL) {
        const host_config_t *conf = get_host_config(servername);
        if (conf != NULL) SSL_set_SSL_CTX(ssl, contexts[conf->cert]);
    }
    return SSL_TLSEXT_ERR_OK;
}

void server_free_client(client_ctx_t *ctx) {
    for (int i = 0; i < list_size(clients); i++) {
        if (clients[i] == ctx) {
            clients = list_remove(clients, i);
            break;
        }
    }
    free(ctx);
}

static void accept_cb(void *arg) {
    int i = (int) (((int *) arg) - sockets);
    int fd = sockets[i];

    client_ctx_t *client_ctx = malloc(sizeof(client_ctx_t));
    if (client_ctx == NULL) {
        critical("Unable to allocate memory for client context");
        errno = 0;
        return;
    }

    clients = list_append(clients, &client_ctx);
    if (clients == NULL) {
        critical("Unable to add client context to list");
        errno = 0;
        return;
    }

    client_ctx->in_use = 1;
    sock *client = &client_ctx->socket;

    client->ctx = contexts[0];
    socklen_t addr_len = sizeof(client->_addr);
    int client_fd = accept(fd, &client->_addr.sock, &addr_len);
    if (client_fd < 0) {
        critical("Unable to accept connection");
        return;
    }

    client->socket = client_fd;
    client->enc = (i == 1);

    tcp_accept(client_ctx);
}

static void accept_err_cb(void *arg) {
    int i = (int) (((int *) arg) - sockets);
    int fd = sockets[i];
    // TODO accept error callback
}

static void terminate_forcefully(int sig) {
    fprintf(stderr, "\n");
    notice("Terminating forcefully!");

    geoip_free();

    notice("Goodbye");
    exit(2);
}

static void terminate_gracefully(int sig) {
    fprintf(stderr, "\n");
    notice("Terminating gracefully...");

    struct sigaction act = {0};
    act.sa_handler = terminate_forcefully;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);

    for (int i = 0; i < NUM_SOCKETS; i++) {
        close(sockets[i]);
    }

    cache_stop();
    workers_stop();
    workers_destroy();

    for (int i = 0; i < list_size(clients); i++) {
        tcp_close(clients[i]);
    }
    proxy_close_all();
    logger_set_prefix("");

    async_stop();
}

static void nothing(int sig) {}

int main(int argc, char *const argv[]) {
    const int YES = 1;
    int ret;

    memset(sockets, 0, sizeof(sockets));
    clients = list_create(sizeof(void *), 64);
    if (clients == NULL) {
        critical("Unable to initialize client list");
        return 1;
    }

    const struct sockaddr_in6 addresses[2] = {
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(80)},
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(443)}
    };

    logger_init();

    logger_set_name("server");

    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0 || setvbuf(stderr, NULL, _IOLBF, 0) != 0) {
        critical("Unable to set stdout/stderr to line-buffered mode");
        return 1;
    }
    printf("sesimos web server " SERVER_VERSION "\n");

    static const struct option long_opts[] = {
            {"help",    no_argument,        0, 'h'},
            {"config",  required_argument,  0, 'c'},
            { 0,        0,                  0,  0 }
    };

    config_file = NULL;
    int c, opt_idx;
    while ((c = getopt_long(argc, argv, "hc:", long_opts, &opt_idx)) != -1) {
        switch (c) {
            case 'h':
                fprintf(stderr,
                        "Usage: sesimos [-h] [-c <CONFIG FILE>]\n"
                        "\n"
                        "Options:\n"
                        "  -c, --config <CONFIG-FILE>  path to the config file. If not provided, default will be used\n"
                        "  -h, --help                  print this dialogue\n");
                return 0;
            case 'c':
                config_file = optarg;
                break;
            case '?':
            default:
                critical("Unable to parse arguments");
                return 1;
        }
    }

    if (optind != argc) {
        critical("No positional arguments expected");
        return 1;
    }

    if (config_load(config_file == NULL ? DEFAULT_CONFIG_FILE : config_file) != 0)
        return 1;

    if ((sockets[0] = socket(AF_INET6, SOCK_STREAM, 0)) == -1 ||
        (sockets[1] = socket(AF_INET6, SOCK_STREAM, 0)) == -1)
    {
        critical("Unable to create socket");
        return 1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (setsockopt(sockets[i], SOL_SOCKET, SO_REUSEADDR, &YES, sizeof(YES)) < 0) {
            critical("Unable to set options for socket %i", i);
            return 1;
        }
    }

    if (bind(sockets[0], (struct sockaddr *) &addresses[0], sizeof(addresses[0])) == -1 ||
        bind(sockets[1], (struct sockaddr *) &addresses[1], sizeof(addresses[1])) == -1)
    {
        critical("Unable to bind socket to address");
        return 1;
    }

    struct sigaction act = {0};
    act.sa_handler = terminate_gracefully;
    sigaction(SIGINT, &act, NULL);
    sigaction(SIGTERM, &act, NULL);
    act.sa_handler = nothing;
    sigaction(SIGUSR1, &act, NULL);
    sigaction(SIGPIPE, &act, NULL);

    if ((ret = geoip_init(config.geoip_dir)) != 0) {
        if (ret == -1) {
            critical("Unable to initialize geoip");
        }
        return 1;
    }

    if ((ret = cache_init()) != 0) {
        geoip_free();
        if (ret == -1) critical("Unable to initialize cache");
        return 1;
    }

    for (int i = 0; i < CONFIG_MAX_CERT_CONFIG; i++) {
        const cert_config_t *conf = &config.certs[i];
        if (conf->name[0] == 0) break;

        contexts[i] = SSL_CTX_new(TLS_server_method());
        SSL_CTX *ctx = contexts[i];
        SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
        SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4");
        SSL_CTX_set_ecdh_auto(ctx, 1);
        SSL_CTX_set_tlsext_servername_callback(ctx, ssl_servername_cb);

        if (SSL_CTX_use_certificate_chain_file(ctx, conf->full_chain) != 1) {
            critical("Unable to load certificate chain file: %s: %s", ERR_reason_error_string(ERR_get_error()), conf->full_chain);
            geoip_free();
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, conf->priv_key, SSL_FILETYPE_PEM) != 1) {
            critical("Unable to load private key file: %s: %s", ERR_reason_error_string(ERR_get_error()), conf->priv_key);
            geoip_free();
            return 1;
        }
    }

    if (async_init() != 0) {
        critical("Unable to initialize async thread");
        geoip_free();
        return 1;
    }

    if (proxy_preload() != 0) {
        critical("Unable to initialize proxy");
        geoip_free();
        async_free();
        return 1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (listen(sockets[i], LISTEN_BACKLOG) < 0) {
            critical("Unable to listen on socket %i", i);
            geoip_free();
            proxy_unload();
            return 1;
        }
    }

    workers_init();

    for (int i = 0; i < NUM_SOCKETS; i++) {
        async_fd(sockets[i], ASYNC_WAIT_READ, ASYNC_KEEP, &sockets[i], accept_cb, accept_err_cb);
    }

    notice("Ready to accept connections");

    async_thread();

    notice("Goodbye!");

    // cleanup
    list_free(clients);
    geoip_free();
    proxy_unload();
    cache_join();
    async_free();
    return 0;
}
