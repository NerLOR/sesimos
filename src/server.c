/**
 * Sesimos - secure, simple, modern web server
 * @brief Main executable
 * @file src/server.c
 * @author Lorenz Stechauner
 * @date 2020-12-03
 */

#include "defs.h"
#include "server.h"
#include "client.h"
#include "logger.h"

#include "lib/cache.h"
#include "lib/config.h"
#include "lib/sock.h"
#include "lib/proxy.h"
#include "lib/geoip.h"
#include "lib/utils.h"

#include <stdio.h>
#include <getopt.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>


volatile sig_atomic_t alive = 1;
const char *config_file;

static int sockets[NUM_SOCKETS];
static sock clients[MAX_CHILDREN];
static pthread_t children[MAX_CHILDREN];
static SSL_CTX *contexts[CONFIG_MAX_CERT_CONFIG];

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

static void accept_cb() {

}

static void accept_err_cb() {

}

static void terminate_forcefully(int sig) {
    fprintf(stderr, "\n");
    notice("Terminating forcefully!");

    int ret;
    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (children[i] != 0) {
            if ((ret = pthread_kill(children[i], SIGKILL)) < 0) {
                errno = ret;
                error("Unable to wait for child process (PID %i)", children[i]);
                errno = 0;
            }
        }
    }

    geoip_free();
    exit(2);
}

static void terminate_gracefully(int sig) {
    fprintf(stderr, "\n");
    notice("Terminating gracefully...");

    alive = 0;
    signal(SIGINT, terminate_forcefully);
    signal(SIGTERM, terminate_forcefully);

    for (int i = 0; i < NUM_SOCKETS; i++) {
        shutdown(sockets[i], SHUT_RDWR);
        close(sockets[i]);
    }

    int ret;
    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (children[i] != 0) {
            ret = pthread_kill(children[i], SIGKILL);
            if (ret < 0) {
                critical("Unable to wait for child process (PID %i)", children[i]);
            } else if (ret == children[i]) {
                children[i] = 0;
            }
        }
    }

    info("Goodbye");
    geoip_free();
    exit(0);
}

int main(int argc, char *const argv[]) {
    const int YES = 1;
    struct pollfd poll_fds[NUM_SOCKETS];
    int ready_sockets_num;
    long client_num = 0;
    int ret;

    memset(sockets, 0, sizeof(sockets));
    memset(children, 0, sizeof(children));

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
    printf("Sesimos web server " SERVER_VERSION "\n");

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

    signal(SIGINT, terminate_gracefully);
    signal(SIGTERM, terminate_gracefully);

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

    proxy_preload();

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (listen(sockets[i], LISTEN_BACKLOG) < 0) {
            critical("Unable to listen on socket %i", i);
            geoip_free();
            return 1;
        }
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        poll_fds[i].fd = sockets[i];
        poll_fds[i].events = POLLIN;
    }

    errno = 0;
    notice("Ready to accept connections");

    while (alive) {
        ready_sockets_num = poll(poll_fds, NUM_SOCKETS, 1000);
        if (ready_sockets_num < 0) {
            critical("Unable to poll sockets");
            terminate_gracefully(0);
            return 1;
        }

        for (int i = 0; i < NUM_SOCKETS; i++) {
            if (poll_fds[i].revents & POLLIN) {
                int j;
                for (j = 0; j < MAX_CHILDREN; j++) {
                    if (children[j] == 0) break;
                }
                sock *client = &clients[j];

                client->ctx = contexts[0];
                socklen_t addr_len = sizeof(client->addr);
                int client_fd = accept(sockets[i], &client->addr.sock, &addr_len);
                if (client_fd < 0) {
                    critical("Unable to accept connection");
                    continue;
                }

                client->socket = client_fd;
                client->enc = (i == 1);
                ret = pthread_create(&children[j], NULL, (void *(*)(void *)) &client_handler, client);
                if (ret != 0) {
                    errno = ret;
                    critical("Unable to create child process");
                }

                client_num++;
            }
        }

        // TODO outsource in thread
        /*
        void *ret_val = NULL;
        for (int i = 0; i < MAX_CHILDREN; i++) {
            if (children[i] != 0) {
                ret = pthread_timed(children[i], &ret_val);
                if (ret < 0) {
                    critical("Unable to wait for thread (PID %i)", children[i]);
                } else if (ret == children[i]) {
                    children[i] = 0;
                }
            }
        }
        */
    }

    geoip_free();
    return 0;
}
