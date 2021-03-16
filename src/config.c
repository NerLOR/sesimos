/**
 * Necronda Web Server
 * Configuration file loader
 * src/config.c
 * Lorenz Stechauner, 2021-01-05
 */

#include "config.h"


int config_init() {
    int shm_id = shmget(SHM_KEY_CONFIG, MAX_HOST_CONFIG * sizeof(host_config), IPC_CREAT | IPC_EXCL | 0640);
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
    memset(config, 0, MAX_HOST_CONFIG * sizeof(host_config));
    shmdt(shm_rw);
    config = shm;
    return 0;
}

int config_unload() {
    int shm_id = shmget(SHM_KEY_CONFIG, 0, 0);
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
    char *conf = malloc(len);
    fread(conf, 1, len, file);
    fclose(file);

    host_config *tmp_config = malloc(MAX_HOST_CONFIG * sizeof(host_config));
    memset(tmp_config, 0, MAX_HOST_CONFIG * sizeof(host_config));

    int i = 0;
    int mode = 0;
    char *ptr = NULL;
    char host[256], *source, *target;
    host[0] = 0;
    while ((ptr = strtok(ptr == NULL ? conf :  NULL, "\n")) != NULL) {
        char *comment = strchr(ptr, '#');
        if (comment != NULL) comment[0] = 0;
        len = strlen(ptr);
        if (ptr[0] == '[') {
            if (ptr[len - 1] != ']') goto err;
            strncpy(tmp_config[i].name, ptr + 1, len - 2);
            i++;
            continue;
        } else if (i == 0) {
            if (len > 12 && strncmp(ptr, "certificate", 11) == 0 && (ptr[11] == ' ' || ptr[11] == '\t')) {
                source = ptr + 11;
                target = cert_file;
            } else if (len > 12 && strncmp(ptr, "private_key", 11) == 0 && (ptr[11] == ' ' || ptr[11] == '\t')) {
                source = ptr + 11;
                target = key_file;
            } else if (len > 10 && strncmp(ptr, "geoip_dir", 9) == 0 && (ptr[9] == ' ' || ptr[9] == '\t')) {
                source = ptr + 9;
                target = geoip_dir;
            } else if (len > 11 && strncmp(ptr, "dns_server", 10) == 0 && (ptr[10] == ' ' || ptr[10] == '\t')) {
                source = ptr + 10;
                target = dns_server;
            }
        } else {
            host_config *hc = &tmp_config[i - 1];
            if (len > 8 && strncmp(ptr, "webroot", 7) == 0 && (ptr[7] == ' ' || ptr[7] == '\t')) {
                source = ptr + 7;
                target = hc->local.webroot;
                if (hc->type != 0 && hc->type != CONFIG_TYPE_LOCAL) {
                    goto err;
                } else {
                    hc->type = CONFIG_TYPE_LOCAL;
                }
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
            }
        }
        char *end_ptr = source + strlen(source) - 1;
        while (source[0] == ' ' || source[0] == '\t') source++;
        while (end_ptr[0] == ' ' || end_ptr[0] == '\t') end_ptr--;
        if (end_ptr <= source) {
            err:
            free(conf);
            free(tmp_config);
            fprintf(stderr, ERR_STR "Unable to parse config file" CLR_STR "\n");
            return -2;
        }
        end_ptr[1] = 0;
        if (target != NULL) {
            strcpy(target, source);
        } else if (mode == 1) {
            if (strcmp(source, "forbidden") == 0) {
                tmp_config[i - 1].local.dir_mode = URI_DIR_MODE_FORBIDDEN;
            } else if (strcmp(source, "info") == 0) {
                tmp_config[i - 1].local.dir_mode = URI_DIR_MODE_INFO;
            } else if (strcmp(source, "list") == 0) {
                tmp_config[i - 1].local.dir_mode = URI_DIR_MODE_LIST;
            } else {
                goto err;
            }
        } else if (mode == 2) {
            tmp_config[i - 1].rev_proxy.port = (unsigned short) strtoul(source, NULL, 10);
        }
    }
    free(conf);

    for (int j = 0; j < i - 1; j++) {
        if (tmp_config[j].type == CONFIG_TYPE_LOCAL) {
            char *webroot = tmp_config[j].local.webroot;
            if (webroot[strlen(webroot) - 1] == '/') {
                webroot[strlen(webroot) - 1] = 0;
            }
        }
    }

    int shm_id = shmget(SHM_KEY_CONFIG, 0, 0);
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
    memcpy(shm_rw, tmp_config, MAX_HOST_CONFIG * sizeof(host_config));
    free(tmp_config);
    shmdt(shm_rw);
    return 0;
}
