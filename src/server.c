/**
 * Sesimos - secure, simple, modern web server
 * @brief Main executable
 * @file src/server.c
 * @author Lorenz Stechauner
 * @date 2020-12-03
 */

#define _POSIX_C_SOURCE 199309L

#include "defs.h"
#include "server.h"
#include "client.h"

#include "lib/cache.h"
#include "lib/config.h"
#include "lib/sock.h"
#include "lib/rev_proxy.h"
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
#include <dirent.h>


volatile sig_atomic_t active = 1;
const char *config_file;
int sockets[NUM_SOCKETS];
pid_t children[MAX_CHILDREN];
MMDB_s mmdbs[MAX_MMDB];
SSL_CTX *contexts[CONFIG_MAX_CERT_CONFIG];

void openssl_init(void) {
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

static int ssl_servername_cb(SSL *ssl, int *ad, void *arg) {
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (servername != NULL) {
        const host_config *conf = get_host_config(servername);
        if (conf != NULL) SSL_set_SSL_CTX(ssl, contexts[conf->cert]);
    }
    return SSL_TLSEXT_ERR_OK;
}

void destroy(int _) {
    fprintf(stderr, "\n" ERR_STR "Terminating forcefully!" CLR_STR "\n");
    int status = 0;
    int ret;
    int kills = 0;
    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (children[i] != 0) {
            ret = waitpid(children[i], &status, WNOHANG);
            if (ret < 0) {
                fprintf(stderr, ERR_STR "Unable to wait for child process (PID %i): %s" CLR_STR "\n", children[i], strerror(errno));
            } else if (ret == children[i]) {
                children[i] = 0;
                if (status != 0) {
                    fprintf(stderr, ERR_STR "Child process with PID %i terminated with exit code %i" CLR_STR "\n", ret, status);
                }
            } else {
                kill(children[i], SIGKILL);
                kills++;
            }
        }
    }
    if (kills > 0) {
        fprintf(stderr, ERR_STR "Killed %i child process(es)" CLR_STR "\n", kills);
    }
    cache_unload();
    config_unload();
    exit(2);
}

void terminate(int _) {
    fprintf(stderr, "\nTerminating gracefully...\n");
    active = 0;

    signal(SIGINT, destroy);
    signal(SIGTERM, destroy);

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
                fprintf(stderr, ERR_STR "Unable to wait for child process (PID %i): %s" CLR_STR "\n", children[i], strerror(errno));
            } else if (ret == children[i]) {
                children[i] = 0;
                if (status != 0) {
                    fprintf(stderr, ERR_STR "Child process with PID %i terminated with exit code %i" CLR_STR "\n", ret, status);
                }
            } else {
                kill(children[i], SIGTERM);
                wait_num++;
            }
        }
    }

    if (wait_num > 0) {
        fprintf(stderr, "Waiting for %i child process(es)...\n", wait_num);
    }

    for (int i = 0; i < MAX_CHILDREN; i++) {
        if (children[i] != 0) {
            ret = waitpid(children[i], &status, 0);
            if (ret < 0) {
                fprintf(stderr, ERR_STR "Unable to wait for child process (PID %i): %s" CLR_STR "\n", children[i], strerror(errno));
            } else if (ret == children[i]) {
                children[i] = 0;
                if (status != 0) {
                    fprintf(stderr, ERR_STR "Child process with PID %i terminated with exit code %i" CLR_STR "\n", ret, status);
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
        fprintf(stderr, "\nGoodbye\n");
    } else {
        fprintf(stderr, "Goodbye\n");
    }
    cache_unload();
    config_unload();
    exit(0);
}

int main(int argc, const char *argv[]) {
    const int YES = 1;
    struct pollfd poll_fds[NUM_SOCKETS];
    int ready_sockets_num;
    long client_num = 0;
    char buf[1024];
    int ret;

    int client_fd;
    sock client;
    struct sockaddr_in6 client_addr;
    unsigned int client_addr_len = sizeof(client_addr);

    memset(sockets, 0, sizeof(sockets));
    memset(children, 0, sizeof(children));
    memset(mmdbs, 0, sizeof(mmdbs));

    const struct sockaddr_in6 addresses[2] = {
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(80)},
            {.sin6_family = AF_INET6, .sin6_addr = IN6ADDR_ANY_INIT, .sin6_port = htons(443)}
    };

    if (setvbuf(stdout, NULL, _IOLBF, 0) != 0) {
        fprintf(stderr, ERR_STR "Unable to set stdout to line-buffered mode: %s" CLR_STR, strerror(errno));
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
                fprintf(stderr, ERR_STR "Unable to parse argument %s, usage: --config <CONFIG-FILE>" CLR_STR "\n", arg);
                config_unload();
                return 1;
            }
            config_file = argv[++i];
        } else {
            fprintf(stderr, ERR_STR "Unable to parse argument '%s'" CLR_STR "\n", arg);
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
        fprintf(stderr, ERR_STR "Unable to create socket: %s" CLR_STR "\n", strerror(errno));
        config_unload();
        return 1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (setsockopt(sockets[i], SOL_SOCKET, SO_REUSEADDR, &YES, sizeof(YES)) < 0) {
            fprintf(stderr, ERR_STR "Unable to set options for socket %i: %s" CLR_STR "\n", i, strerror(errno));
            config_unload();
            return 1;
        }
    }

    if (bind(sockets[0], (struct sockaddr *) &addresses[0], sizeof(addresses[0])) < 0) goto bind_err;
    if (bind(sockets[1], (struct sockaddr *) &addresses[1], sizeof(addresses[1])) < 0) {
        bind_err:
        fprintf(stderr, ERR_STR "Unable to bind socket to address: %s" CLR_STR "\n", strerror(errno));
        config_unload();
        return 1;
    }

    signal(SIGINT, terminate);
    signal(SIGTERM, terminate);

    if (geoip_dir[0] != 0) {
        DIR *geoip = opendir(geoip_dir);
        if (geoip == NULL) {
            fprintf(stderr, ERR_STR "Unable to open GeoIP dir: %s" CLR_STR "\n", strerror(errno));
            config_unload();
            return 1;
        }
        struct dirent *dir;
        int i = 0;
        while ((dir = readdir(geoip)) != NULL) {
            if (strcmp(dir->d_name + strlen(dir->d_name) - 5, ".mmdb") != 0) continue;
            if (i >= MAX_MMDB) {
                fprintf(stderr, ERR_STR "Too many .mmdb files" CLR_STR "\n");
                config_unload();
                return 1;
            }
            sprintf(buf, "%s/%s", geoip_dir, dir->d_name);
            ret = MMDB_open(buf, 0, &mmdbs[i]);
            if (ret != MMDB_SUCCESS) {
                fprintf(stderr, ERR_STR "Unable to open .mmdb file: %s" CLR_STR "\n", MMDB_strerror(ret));
                config_unload();
                return 1;
            }
            i++;
        }
        if (i == 0) {
            fprintf(stderr, ERR_STR "No .mmdb files found in %s" CLR_STR "\n", geoip_dir);
            config_unload();
            return 1;
        }
        closedir(geoip);
    }

    ret = cache_init();
    if (ret < 0) {
        config_unload();
        return 1;
    } else if (ret != 0) {
        children[0] = ret;  // pid
    } else {
        return 0;
    }

    openssl_init();

    client.buf = NULL;
    client.buf_len = 0;
    client.buf_off = 0;

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
            fprintf(stderr, ERR_STR "Unable to load certificate chain file: %s: %s" CLR_STR "\n", ERR_reason_error_string(ERR_get_error()), conf->full_chain);
            config_unload();
            cache_unload();
            return 1;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, conf->priv_key, SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, ERR_STR "Unable to load private key file: %s: %s" CLR_STR "\n", ERR_reason_error_string(ERR_get_error()), conf->priv_key);
            config_unload();
            cache_unload();
            return 1;
        }
    }

    client.ctx = contexts[0];


    rev_proxy_preload();

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (listen(sockets[i], LISTEN_BACKLOG) < 0) {
            fprintf(stderr, ERR_STR "Unable to listen on socket %i: %s" CLR_STR "\n", i, strerror(errno));
            config_unload();
            cache_unload();
            return 1;
        }
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        poll_fds[i].fd = sockets[i];
        poll_fds[i].events = POLLIN;
    }

    fprintf(stderr, "Ready to accept connections\n");

    while (active) {
        ready_sockets_num = poll(poll_fds, NUM_SOCKETS, 1000);
        if (ready_sockets_num < 0) {
            fprintf(stderr, ERR_STR "Unable to poll sockets: %s" CLR_STR "\n", strerror(errno));
            terminate(0);
            return 1;
        }

        for (int i = 0; i < NUM_SOCKETS; i++) {
            if (poll_fds[i].revents & POLLIN) {
                client_fd = accept(sockets[i], (struct sockaddr *) &client_addr, &client_addr_len);
                if (client_fd < 0) {
                    fprintf(stderr, ERR_STR "Unable to accept connection: %s" CLR_STR "\n", strerror(errno));
                    continue;
                }

                pid_t pid = fork();
                if (pid == 0) {
                    // child
                    signal(SIGINT, SIG_IGN);
                    signal(SIGTERM, SIG_IGN);

                    client.socket = client_fd;
                    client.enc = (i == 1);
                    return client_handler(&client, client_num, &client_addr);
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
                    fprintf(stderr, ERR_STR "Unable to create child process: %s" CLR_STR "\n", strerror(errno));
                }
            }
        }

        // TODO outsource in thread
        int status = 0;
        for (int i = 0; i < MAX_CHILDREN; i++) {
            if (children[i] != 0) {
                ret = waitpid(children[i], &status, WNOHANG);
                if (ret < 0) {
                    fprintf(stderr, ERR_STR "Unable to wait for child process (PID %i): %s" CLR_STR "\n", children[i], strerror(errno));
                } else if (ret == children[i]) {
                    children[i] = 0;
                    if (status != 0) {
                        fprintf(stderr, ERR_STR "Child process with PID %i terminated with exit code %i" CLR_STR "\n", ret, status);
                    }
                }
            }
        }
    }

    config_unload();
    cache_unload();
    return 0;
}
