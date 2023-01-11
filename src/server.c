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
#include "lib/utils.h"

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

static void clean(void) {
    notice("Cleaning sesimos cache and metadata files...");

    // remove legacy files
    //     /.../server/, /.../server/cache
    if (rm_rf("/var/sesimos/server") != 0) {
        error("Unable to remove /var/sesimos/server/");
    } else if (!errno) {
        notice("Successfully removed /var/sesimos/server/");
    }
    errno = 0;

    // remove cache and metadata files
    char buf[512];
    for (int i = 0; i < CONFIG_MAX_HOST_CONFIG; i++) {
        host_config_t *hc = &config.hosts[i];
        if (hc->type == CONFIG_TYPE_UNSET) break;
        if (hc->type != CONFIG_TYPE_LOCAL) continue;

        snprintf(buf, sizeof(buf), "%s/.sesimos", hc->local.webroot);
        if (rm_rf(buf) != 0) {
            error("Unable to remove %s/", buf);
        } else if (!errno) {
            notice("Successfully removed %s/", buf);
        }
        errno = 0;
    }

    notice("Cleaned all sesimos cache and metadata files!");
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
    clients = list_delete(clients, &ctx);
    free(ctx);
}

static void ssl_free() {
    for (int i = 0; i < CONFIG_MAX_CERT_CONFIG; i++) {
        const cert_config_t *conf = &config.certs[i];
        if (conf->name[0] == 0) break;
        SSL_CTX_free(contexts[i]);
    }
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
    client->ts_start = clock_micros();
    client->ts_last = client->ts_start;
    client_ctx->cnx_s = client->ts_start;
    client_ctx->cnx_e = -1, client_ctx->req_s = -1, client_ctx->req_e = -1, client_ctx->res_ts = -1;

    clients = list_append(clients, &client_ctx);
    if (clients == NULL) {
        critical("Unable to add client context to list");
        errno = 0;
        return;
    }

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

    while (list_size(clients) > 0)
        server_free_client(clients[0]);

    proxy_close_all();
    logger_set_prefix("");

    async_stop();
}

static void nothing(int sig) {}

int main(int argc, char *const argv[]) {
    const int YES = 1;
    int ret;
    int mode = 0;

    memset(sockets, 0, sizeof(sockets));

    const struct sockaddr_in6 addresses[2] = {
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(80)},
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(443)}
    };

    logger_set_name("server");

    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0 || setvbuf(stderr, NULL, _IOLBF, 0) != 0) {
        critical("Unable to set stdout/stderr to line-buffered mode");
        return 1;
    }
    printf("sesimos web server " SERVER_VERSION "\n");

    static const struct option long_opts[] = {
            {"help",    no_argument,        0, 'h'},
            {"clean",   no_argument,        0, 'C'},
            {"config",  required_argument,  0, 'c'},
            { 0,        0,                  0,  0 }
    };

    config_file = NULL;
    for (int c, opt_idx; (c = getopt_long(argc, argv, "hCc:", long_opts, &opt_idx)) != -1;) {
        switch (c) {
            case 'h':
                fprintf(stderr,
                        "Usage: sesimos [-h] [-c <CONFIG FILE>]\n"
                        "\n"
                        "Options:\n"
                        "  -c, --config <CONFIG-FILE>  path to the config file. If not provided, default will be used\n"
                        "  -C, --clean                 clear cached files and other metadata\n"
                        "  -h, --help                  print this dialogue\n");
                return 0;
            case 'c':
                config_file = optarg;
                break;
            case 'C':
                mode = 1;
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

    if (mode == 1) {
        clean();
        return 0;
    }

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

    clients = list_create(sizeof(client_ctx_t *), 64);
    if (clients == NULL) {
        critical("Unable to initialize client list");
        ssl_free();
        return 1;
    }

    if (async_init() != 0) {
        critical("Unable to initialize async thread");
        ssl_free();
        geoip_free();
        list_free(clients);
        return 1;
    }

    if (proxy_preload() != 0) {
        critical("Unable to initialize proxy");
        ssl_free();
        geoip_free();
        list_free(clients);
        async_free();
        return 1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (listen(sockets[i], LISTEN_BACKLOG) < 0) {
            critical("Unable to listen on socket %i", i);
            ssl_free();
            geoip_free();
            list_free(clients);
            async_free();
            proxy_unload();
            return 1;
        }
    }

    logger_init();
    logger_set_name("server");

    workers_init();

    for (int i = 0; i < NUM_SOCKETS; i++) {
        async_fd(sockets[i], ASYNC_WAIT_READ, ASYNC_KEEP, &sockets[i], accept_cb, accept_err_cb, accept_err_cb);
    }

    notice("Ready to accept connections");

    async_thread();

    notice("Goodbye!");

    // cleanup
    ssl_free();
    list_free(clients);
    geoip_free();
    proxy_unload();
    cache_join();
    async_free();
    logger_stop();
    logger_join();
    return 0;
}
