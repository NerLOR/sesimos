/**
 * sesimos - secure, simple, modern web server
 * @brief Configuration file loader
 * @file src/lib/config.c
 * @author Lorenz Stechauner
 * @date 2021-01-05
 */

#include "../logger.h"
#include "config.h"
#include "utils.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

config_t config;

static int config_parse_line(char *line, char *section, int *i, int *j) {
    int mode = 0;
    char *source, *target;

    char *ptr = line;
    char *comment = strpbrk(ptr, "#\r\n");
    if (comment != NULL) comment[0] = 0;

    unsigned long len = strlen(ptr);
    char *end_ptr = (len > 0) ? ptr + len - 1 : ptr;
    while (end_ptr[0] == ' ' || end_ptr[0] == '\t') {
        end_ptr[0] = 0;
        end_ptr--;
    }
    len = strlen(ptr);
    if (len == 0) return 0;

    if (ptr[0] == '[') {
        if (ptr[len - 1] != ']') return -1;
        ptr++;
        int l = 0;
        if (strncmp(ptr, "host", 4) == 0 && (ptr[4] == ' ' || ptr[4] == '\t')) {
            ptr += 4;
            while (ptr[0] == ' ' || ptr[0] == '\t' || ptr[0] == ']') ptr++;
            while (ptr[l] != ' ' && ptr[l] != '\t' && ptr[l] != ']') l++;
            if (l == 0) return -1;
            snprintf(config.hosts[*i].name, sizeof(config.hosts[*i].name), "%.*s", l, ptr);
            ++(*i);
            *section = 'h';
        } else if (strncmp(ptr, "cert", 4) == 0 && (ptr[4] == ' ' || ptr[4] == '\t')) {
            ptr += 4;
            while (ptr[0] == ' ' || ptr[0] == '\t' || ptr[0] == ']') ptr++;
            while (ptr[l] != ' ' && ptr[l] != '\t' && ptr[l] != ']') l++;
            if (l == 0) return -1;
            snprintf(config.certs[*j].name, sizeof(config.certs[*j].name), "%.*s", l, ptr);
            ++(*j);
            *section = 'c';
        } else {
            return -1;
        }
        return 0;
    } else if (*section == 0) {
        if (len > 10 && strncmp(ptr, "geoip_dir", 9) == 0 && (ptr[9] == ' ' || ptr[9] == '\t')) {
            source = ptr + 9;
            target = config.geoip_dir;
        } else {
            return -1;
        }
    } else if (*section == 'c') {
        cert_config_t *cc = &config.certs[*j - 1];
        if (len > 12 && strncmp(ptr, "certificate", 11) == 0 && (ptr[11] == ' ' || ptr[11] == '\t')) {
            source = ptr + 11;
            target = cc->full_chain;
        } else if (len > 12 && strncmp(ptr, "private_key", 11) == 0 && (ptr[11] == ' ' || ptr[11] == '\t')) {
            source = ptr + 11;
            target = cc->priv_key;
        } else {
            return -1;
        }
    } else if (*section == 'h') {
        host_config_t *hc = &config.hosts[*i - 1];
        if (len > 8 && strncmp(ptr, "webroot", 7) == 0 && (ptr[7] == ' ' || ptr[7] == '\t')) {
            source = ptr + 7;
            target = hc->local.webroot;
            if (hc->type != 0 && hc->type != CONFIG_TYPE_LOCAL) {
                return -1;
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
                return -1;
            } else {
                hc->type = CONFIG_TYPE_LOCAL;
            }
        } else if (len > 9 && strncmp(ptr, "hostname", 8) == 0 && (ptr[8] == ' ' || ptr[8] == '\t')) {
            source = ptr + 8;
            target = hc->proxy.hostname;
            if (hc->type != 0 && hc->type != CONFIG_TYPE_REVERSE_PROXY) {
                return -1;
            } else {
                hc->type = CONFIG_TYPE_REVERSE_PROXY;
            }
        } else if (len > 5 && strncmp(ptr, "port", 4) == 0 && (ptr[4] == ' ' || ptr[4] == '\t')) {
            source = ptr + 4;
            target = NULL;
            mode = 2;
            if (hc->type != 0 && hc->type != CONFIG_TYPE_REVERSE_PROXY) {
                return -1;
            } else {
                hc->type = CONFIG_TYPE_REVERSE_PROXY;
            }
        } else if (streq(ptr, "http")) {
            if (hc->type != 0 && hc->type != CONFIG_TYPE_REVERSE_PROXY) {
                return -1;
            } else {
                hc->type = CONFIG_TYPE_REVERSE_PROXY;
                hc->proxy.enc = 0;
            }
            return 0;
        } else if (streq(ptr, "https")) {
            if (hc->type != 0 && hc->type != CONFIG_TYPE_REVERSE_PROXY) {
                return -1;
            } else {
                hc->type = CONFIG_TYPE_REVERSE_PROXY;
                hc->proxy.enc = 1;
            }
            return 0;
        } else {
            return -1;
        }
    } else {
        return -1;
    }

    while (source[0] == ' ' || source[0] == '\t') source++;
    if (strlen(source) == 0) return -1;

    if (target != NULL) {
        strcpy(target, source);
    } else if (mode == 1) {
        if (streq(source, "forbidden")) {
            config.hosts[*i - 1].local.dir_mode = URI_DIR_MODE_FORBIDDEN;
        } else if (streq(source, "info")) {
            config.hosts[*i - 1].local.dir_mode = URI_DIR_MODE_INFO;
        } else if (streq(source, "list")) {
            config.hosts[*i - 1].local.dir_mode = URI_DIR_MODE_LIST;
        } else {
            return -1;
        }
    } else if (mode == 2) {
        config.hosts[*i - 1].proxy.port = (unsigned short) strtoul(source, NULL, 10);
    }

    return 0;
}

int config_load(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        critical("Unable to open config file");
        return -1;
    }

    memset(&config, 0, sizeof(config));

    int i = 0, j = 0;
    char section = 0;

    char *line = NULL;
    size_t line_len = 0;
    for (int line_num = 1; getline(&line, &line_len, file) != -1; line_num++) {
        if (config_parse_line(line, &section, &i, &j) != 0) {
            critical("Unable to parse config file (line %i)", line_num);
            free(line);
            fclose(file);
            return -2;
        }
    }

    free(line);
    fclose(file);

    for (int k = 0; k < i; k++) {
        host_config_t *hc = &config.hosts[k];
        if (hc->type == CONFIG_TYPE_LOCAL) {
            char *webroot = config.hosts[k].local.webroot;
            while (webroot[strlen(webroot) - 1] == '/') webroot[strlen(webroot) - 1] = 0;
        }

        if (hc->cert_name[0] == 0) {
            critical("Unable to parse config file: host config (%s) does not contain a certificate", hc->name);
            return -2;
        }

        int found = 0;
        for (int m = 0; m < j; m++) {
            if (streq(config.certs[m].name, hc->cert_name)) {
                hc->cert = m;
                found = 1;
                break;
            }
        }
        if (!found) {
            critical("Unable to parse config file: certificate (%s) for host config (%s) not found", hc->cert_name, hc->name);
            return -2;
        }
    }

    return 0;
}

host_config_t *get_host_config(const char *host) {
    for (int i = 0; i < CONFIG_MAX_HOST_CONFIG; i++) {
        host_config_t *hc = &config.hosts[i];
        if (hc->type == CONFIG_TYPE_UNSET) break;
        if (streq(hc->name, host)) return hc;
        if (hc->name[0] == '*' && hc->name[1] == '.') {
            const char *pos = strstr(host, hc->name + 1);
            if (pos != NULL && strlen(pos) == strlen(hc->name + 1)) return hc;
        }
    }
    return NULL;
}
