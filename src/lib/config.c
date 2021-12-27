/**
 * Necronda Web Server
 * Configuration file loader
 * src/lib/config.c
 * Lorenz Stechauner, 2021-01-05
 */

#include "config.h"
#include "utils.h"
#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>

t_config *config;
char geoip_dir[256], dns_server[256];

int config_init() {
    int shm_id = shmget(CONFIG_SHM_KEY, sizeof(t_config), IPC_CREAT | IPC_EXCL | 0640);
    if (shm_id < 0) {
        fprintf(stderr, ERR_STR "Unable to create shared memory: %s" CLR_STR "\n", strerror(errno));
        return -1;
    }

    void *shm = shmat(shm_id, NULL, SHM_RDONLY);
    if (shm == (void *) -1) {
        fprintf(stderr, ERR_STR "Unable to attach shared memory (ro): %s" CLR_STR "\n", strerror(errno));
        return -2;
    }
    config = shm;

    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        fprintf(stderr, ERR_STR "Unable to attach shared memory (rw): %s" CLR_STR "\n", strerror(errno));
        return -3;
    }
    config = shm_rw;
    memset(config, 0, sizeof(t_config));
    shmdt(shm_rw);
    config = shm;
    return 0;
}

int config_unload() {
    int shm_id = shmget(CONFIG_SHM_KEY, 0, 0);
    if (shm_id < 0) {
        fprintf(stderr, ERR_STR "Unable to get shared memory id: %s" CLR_STR "\n", strerror(errno));
        shmdt(config);
        return -1;
    } else if (shmctl(shm_id, IPC_RMID, NULL) < 0) {
        fprintf(stderr, ERR_STR "Unable to configure shared memory: %s" CLR_STR "\n", strerror(errno));
        shmdt(config);
        return -1;
    }
    shmdt(config);
    return 0;
}

int config_load(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        fprintf(stderr, ERR_STR "Unable to open config file: %s" CLR_STR "\n", strerror(errno));
        return -1;
    }

    fseek(file, 0, SEEK_END);
    unsigned long len = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *conf = alloca(len);
    fread(conf, 1, len, file);
    fclose(file);

    t_config *tmp_config = malloc(sizeof(t_config));
    memset(tmp_config, 0, sizeof(t_config));

    int i = 0;
    int j = 0;
    int line = 0;
    int mode = 0;
    char section = 0;
    char *ptr = NULL;
    char *source, *target;
    while ((ptr = strsep(&conf, "\r\n")) != NULL) {
        line++;
        char *comment = strchr(ptr, '#');
        if (comment != NULL) comment[0] = 0;

        len = strlen(ptr);
        char *end_ptr = ptr + len - 1;
        while (end_ptr[0] == ' ' || end_ptr[0] == '\t') {
            end_ptr[0] = 0;
            end_ptr--;
        }
        len = strlen(ptr);
        if (len == 0) continue;

        if (ptr[0] == '[') {
            if (ptr[len - 1] != ']') goto err;
            ptr++;
            int l = 0;
            if (strncmp(ptr, "host", 4) == 0 && (ptr[4] == ' ' || ptr[4] == '\t')) {
                ptr += 4;
                while (ptr[0] == ' ' || ptr[0] == '\t' || ptr[0] == ']') ptr++;
                while (ptr[l] != ' ' && ptr[l] != '\t' && ptr[l] != ']') l++;
                if (l == 0) goto err;
                snprintf(tmp_config->hosts[i].name, sizeof(tmp_config->hosts[i].name), "%.*s", l, ptr);
                i++;
                section = 'h';
            } else if (strncmp(ptr, "cert", 4) == 0 && (ptr[4] == ' ' || ptr[4] == '\t')) {
                ptr += 4;
                while (ptr[0] == ' ' || ptr[0] == '\t' || ptr[0] == ']') ptr++;
                while (ptr[l] != ' ' && ptr[l] != '\t' && ptr[l] != ']') l++;
                if (l == 0) goto err;
                snprintf(tmp_config->certs[j].name, sizeof(tmp_config->certs[j].name), "%.*s", l, ptr);
                j++;
                section = 'c';
            } else {
                goto err;
            }
            continue;
        } else if (section == 0) {
            if (len > 10 && strncmp(ptr, "geoip_dir", 9) == 0 && (ptr[9] == ' ' || ptr[9] == '\t')) {
                source = ptr + 9;
                target = geoip_dir;
            } else if (len > 11 && strncmp(ptr, "dns_server", 10) == 0 && (ptr[10] == ' ' || ptr[10] == '\t')) {
                source = ptr + 10;
                target = dns_server;
            } else {
                goto err;
            }
        } else if (section == 'c') {
            cert_config *cc = &tmp_config->certs[j - 1];
            if (len > 12 && strncmp(ptr, "certificate", 11) == 0 && (ptr[11] == ' ' || ptr[11] == '\t')) {
                source = ptr + 11;
                target = cc->full_chain;
            } else if (len > 12 && strncmp(ptr, "private_key", 11) == 0 && (ptr[11] == ' ' || ptr[11] == '\t')) {
                source = ptr + 11;
                target = cc->priv_key;
            } else {
                goto err;
            }
        } else if (section == 'h') {
            host_config *hc = &tmp_config->hosts[i - 1];
            if (len > 8 && strncmp(ptr, "webroot", 7) == 0 && (ptr[7] == ' ' || ptr[7] == '\t')) {
                source = ptr + 7;
                target = hc->local.webroot;
                if (hc->type != 0 && hc->type != CONFIG_TYPE_LOCAL) {
                    goto err;
                } else {
                    hc->type = CONFIG_TYPE_LOCAL;
                }
            } else if (len > 5 && strncmp(ptr, "cert", 4) == 0 && (ptr[4] == ' ' || ptr[4] == '\t')) {
                source = ptr + 4;
                target = hc->cert_name;
            } else if (len > 9 && strncmp(ptr, "dir_mode", 8) == 0 && (ptr[8] == ' ' || ptr[8] == '\t')) {
                source = ptr + 8;
                target = NULL;
                mode = 1;
                if (hc->type != 0 && hc->type != CONFIG_TYPE_LOCAL) {
                    goto err;
                } else {
                    hc->type = CONFIG_TYPE_LOCAL;
                }
            } else if (len > 9 && strncmp(ptr, "hostname", 8) == 0 && (ptr[8] == ' ' || ptr[8] == '\t')) {
                source = ptr + 8;
                target = hc->rev_proxy.hostname;
                if (hc->type != 0 && hc->type != CONFIG_TYPE_REVERSE_PROXY) {
                    goto err;
                } else {
                    hc->type = CONFIG_TYPE_REVERSE_PROXY;
                }
            } else if (len > 5 && strncmp(ptr, "port", 4) == 0 && (ptr[4] == ' ' || ptr[4] == '\t')) {
                source = ptr + 4;
                target = NULL;
                mode = 2;
                if (hc->type != 0 && hc->type != CONFIG_TYPE_REVERSE_PROXY) {
                    goto err;
                } else {
                    hc->type = CONFIG_TYPE_REVERSE_PROXY;
                }
            } else if (strcmp(ptr, "http") == 0) {
                if (hc->type != 0 && hc->type != CONFIG_TYPE_REVERSE_PROXY) {
                    goto err;
                } else {
                    hc->type = CONFIG_TYPE_REVERSE_PROXY;
                    hc->rev_proxy.enc = 0;
                }
                continue;
            } else if (strcmp(ptr, "https") == 0) {
                if (hc->type != 0 && hc->type != CONFIG_TYPE_REVERSE_PROXY) {
                    goto err;
                } else {
                    hc->type = CONFIG_TYPE_REVERSE_PROXY;
                    hc->rev_proxy.enc = 1;
                }
                continue;
            } else {
                goto err;
            }
        } else {
            goto err;
        }

        while (source[0] == ' ' || source[0] == '\t') source++;
        if (strlen(source) == 0) {
            err:
            free(tmp_config);
            fprintf(stderr, ERR_STR "Unable to parse config file (line %i)" CLR_STR "\n", line);
            return -2;
        }

        if (target != NULL) {
            strcpy(target, source);
        } else if (mode == 1) {
            if (strcmp(source, "forbidden") == 0) {
                tmp_config->hosts[i - 1].local.dir_mode = URI_DIR_MODE_FORBIDDEN;
            } else if (strcmp(source, "info") == 0) {
                tmp_config->hosts[i - 1].local.dir_mode = URI_DIR_MODE_INFO;
            } else if (strcmp(source, "list") == 0) {
                tmp_config->hosts[i - 1].local.dir_mode = URI_DIR_MODE_LIST;
            } else {
                goto err;
            }
        } else if (mode == 2) {
            tmp_config->hosts[i - 1].rev_proxy.port = (unsigned short) strtoul(source, NULL, 10);
        }
    }

    for (int k = 0; k < i; k++) {
        host_config *hc = &tmp_config->hosts[k];
        if (hc->type == CONFIG_TYPE_LOCAL) {
            char *webroot = tmp_config->hosts[k].local.webroot;
            if (webroot[strlen(webroot) - 1] == '/') {
                webroot[strlen(webroot) - 1] = 0;
            }
        }
        if (hc->cert_name[0] == 0) goto err2;
        int found = 0;
        for (int m = 0; m < j; m++) {
            if (strcmp(tmp_config->certs[m].name, hc->cert_name) == 0) {
                hc->cert = m;
                found = 1;
                break;
            }
        }
        if (!found) {
            err2:
            free(tmp_config);
            fprintf(stderr, ERR_STR "Unable to parse config file" CLR_STR "\n");
            return -2;
        }
    }

    int shm_id = shmget(CONFIG_SHM_KEY, 0, 0);
    if (shm_id < 0) {
        fprintf(stderr, ERR_STR "Unable to get shared memory id: %s" CLR_STR "\n", strerror(errno));
        shmdt(config);
        return -3;
    }

    void *shm_rw = shmat(shm_id, NULL, 0);
    if (shm_rw == (void *) -1) {
        free(tmp_config);
        fprintf(stderr, ERR_STR "Unable to attach shared memory (rw): %s" CLR_STR "\n", strerror(errno));
        return -4;
    }
    memcpy(shm_rw, tmp_config, sizeof(t_config));
    free(tmp_config);
    shmdt(shm_rw);
    return 0;
}
