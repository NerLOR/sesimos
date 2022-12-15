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
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <poll.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <wait.h>
#include <sys/types.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>


volatile sig_atomic_t active = 1;
const char *config_file;
int sockets[NUM_SOCKETS];
pid_t children[MAX_CHILDREN];
SSL_CTX *contexts[CONFIG_MAX_CERT_CONFIG];

static int ssl_servername_cb(SSL *ssl, int *ad, void *arg) {
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername != NULL) {
        const host_config *conf = get_host_config(servername);
        if (conf != NULL) SSL_set_SSL_CTX(ssl, contexts[conf->cert]);
    }
    return SSL_TLSEXT_ERR_OK;
}

void terminate_forcefully(int sig) {
    fprintf(stderr, "\n");
    notice("Terminating forcefully!");

    int status = 0;
    int ret;
    int kills = 0;
    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (children[i] != 0) {
            ret = waitpid(children[i], &status, WNOHANG);
            if (ret < 0) {
                error("Unable to wait for child process (PID %i)", children[i]);
            } else if (ret == children[i]) {
                children[i] = 0;
                if (status != 0) {
                    error("Child process with PID %i terminated with exit code %i", ret, status);
                }
            } else {
                kill(children[i], SIGKILL);
                kills++;
            }
        }
    }
    if (kills > 0) {
        notice("Killed %i child process(es)", kills);
    }
    cache_unload();
    config_unload();
    geoip_free();
    exit(2);
}

void terminate_gracefully(int sig) {
    fprintf(stderr, "\n");
    notice("Terminating gracefully...");

    active = 0;
    signal(SIGINT, terminate_forcefully);
    signal(SIGTERM, terminate_forcefully);

    for (int i = 0; i < NUM_SOCKETS; i++) {
        shutdown(sockets[i], SHUT_RDWR);
        close(sockets[i]);
    }

    int status = 0;
    int wait_num = 0;
    int ret;
    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (children[i] != 0) {
            ret = waitpid(children[i], &status, WNOHANG);
            if (ret < 0) {
                critical("Unable to wait for child process (PID %i)", children[i]);
            } else if (ret == children[i]) {
                children[i] = 0;
                if (status != 0) {
                    critical("Child process with PID %i terminated with exit code %i", ret, status);
                }
            } else {
                kill(children[i], SIGTERM);
                wait_num++;
            }
        }
    }

    if (wait_num > 0) {
        notice("Waiting for %i child process(es)...", wait_num);
    }

    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (children[i] != 0) {
            ret = waitpid(children[i], &status, 0);
            if (ret < 0) {
                critical("Unable to wait for child process (PID %i)", children[i]);
            } else if (ret == children[i]) {
                children[i] = 0;
                if (status != 0) {
                    critical("Child process with PID %i terminated with exit code %i", ret, status);
                }
            }
        }
    }

    if (wait_num > 0) {
        // Wait another 50 ms to let child processes write to stdout/stderr
        signal(SIGINT, SIG_IGN);
        signal(SIGTERM, SIG_IGN);
        struct timespec ts = {.tv_sec = 0, .tv_nsec = 50000000};
        nanosleep(&ts, &ts);
    }

    info("Goodbye");
    cache_unload();
    config_unload();
    geoip_free();
    exit(0);
}

int main(int argc, const char *argv[]) {
    const int YES = 1;
    struct pollfd poll_fds[NUM_SOCKETS];
    int ready_sockets_num;
    long client_num = 0;
    int ret;

    int client_fd;
    sock client;

    memset(sockets, 0, sizeof(sockets));
    memset(children, 0, sizeof(children));

    const struct sockaddr_in6 addresses[2] = {
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(80)},
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(443)}
    };

    logger_set_name("server");

    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0 || setvbuf(stderr, NULL, _IOLBF, 0) != 0) {
        critical("Unable to set stdout/stderr to line-buffered mode");
        return 1;
    }
    printf("Sesimos web server " SERVER_VERSION "\n");

    ret = config_init();
    if (ret != 0) {
        return 1;
    }

    config_file = NULL;
    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            printf("Usage: sesimos [-h] [-c <CONFIG-FILE>]\n"
                   "\n"
                   "Options:\n"
                   "  -c, --config <CONFIG-FILE>  path to the config file. If not provided, default will be used\n"
                   "  -h, --help                  print this dialogue\n");
            config_unload();
            return 0;
        } else if (strcmp(arg, "-c") == 0 || strcmp(arg, "--config") == 0) {
            if (i == argc - 1) {
                critical("Unable to parse argument %s, usage: --config <CONFIG-FILE>", arg);
                config_unload();
                return 1;
            }
            config_file = argv[++i];
        } else {
            critical("Unable to parse argument '%s'", arg);
            config_unload();
            return 1;
        }
    }

    ret = config_load(config_file == NULL ? DEFAULT_CONFIG_FILE : config_file);
    if (ret != 0) {
        config_unload();
        return 1;
    }

    sockets[0] = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockets[0] < 0) goto socket_err;
    sockets[1] = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockets[1] < 0) {
        socket_err:
        critical("Unable to create socket");
        config_unload();
        return 1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (setsockopt(sockets[i], SOL_SOCKET, SO_REUSEADDR, &YES, sizeof(YES)) < 0) {
            critical("Unable to set options for socket %i", i);
            config_unload();
            return 1;
        }
    }

    if (bind(sockets[0], (struct sockaddr *) &addresses[0], sizeof(addresses[0])) < 0) goto bind_err;
    if (bind(sockets[1], (struct sockaddr *) &addresses[1], sizeof(addresses[1])) < 0) {
        bind_err:
        critical("Unable to bind socket to address");
        config_unload();
        return 1;
    }

    signal(SIGINT, terminate_gracefully);
    signal(SIGTERM, terminate_gracefully);

    if ((ret = geoip_init(geoip_dir)) != 0) {
        if (ret == -1) {
            critical("Unable to initialize geoip");
        }
        config_unload();
        return 1;
    }

    ret = cache_init();
    if (ret < 0) {
        config_unload();
        geoip_free();
        return 1;
    } else if (ret != 0) {
        children[0] = ret;  // pid
    } else {
        return 0;
    }

    for (int i = 0; i < CONFIG_MAX_CERT_CONFIG; i++) {
        const cert_config *conf = &config->certs[i];
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
            config_unload();
            cache_unload();
            geoip_free();
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, conf->priv_key, SSL_FILETYPE_PEM) != 1) {
            critical("Unable to load private key file: %s: %s", ERR_reason_error_string(ERR_get_error()), conf->priv_key);
            config_unload();
            cache_unload();
            geoip_free();
            return 1;
        }
    }

    client.ctx = contexts[0];


    proxy_preload();

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (listen(sockets[i], LISTEN_BACKLOG) < 0) {
            critical("Unable to listen on socket %i", i);
            config_unload();
            cache_unload();
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

    while (active) {
        ready_sockets_num = poll(poll_fds, NUM_SOCKETS, 1000);
        if (ready_sockets_num < 0) {
            critical("Unable to poll sockets");
            terminate_gracefully(0);
            return 1;
        }

        for (int i = 0; i < NUM_SOCKETS; i++) {
            if (poll_fds[i].revents & POLLIN) {
                socklen_t addr_len = sizeof(client.addr);
                client_fd = accept(sockets[i], &client.addr.sock, &addr_len);
                if (client_fd < 0) {
                    critical("Unable to accept connection");
                    continue;
                }

                pid_t pid = fork();
                if (pid == 0) {
                    // child
                    signal(SIGINT, SIG_IGN);
                    signal(SIGTERM, SIG_IGN);

                    client.socket = client_fd;
                    client.enc = (i == 1);
                    return client_handler(&client, client_num);
                } else if (pid > 0) {
                    // parent
                    client_num++;
                    close(client_fd);
                    for (int j = 0; j < MAX_CHILDREN; j++) {
                        if (children[j] == 0) {
                            children[j] = pid;
                            break;
                        }
                    }
                } else {
                    critical("Unable to create child process");
                }
            }
        }

        // TODO outsource in thread
        int status = 0;
        for (int i = 0; i < MAX_CHILDREN; i++) {
            if (children[i] != 0) {
                ret = waitpid(children[i], &status, WNOHANG);
                if (ret < 0) {
                    critical("Unable to wait for child process (PID %i)", children[i]);
                } else if (ret == children[i]) {
                    children[i] = 0;
                    if (status != 0) {
                        critical("Child process with PID %i terminated with exit code %i", ret, status);
                    }
                }
            }
        }
    }

    config_unload();
    cache_unload();
    geoip_free();
    return 0;
}
