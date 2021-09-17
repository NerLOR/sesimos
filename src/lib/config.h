/**
 * Necronda Web Server
 * Configuration file loader (header file)
 * src/lib/config.h
 * Lorenz Stechauner, 2021-01-05
 */

#ifndef NECRONDA_SERVER_CONFIG_H
#define NECRONDA_SERVER_CONFIG_H

#include "uri.h"

#define CONFIG_SHM_KEY 255642
#define CONFIG_MAX_HOST_CONFIG 64

#define CONFIG_TYPE_UNSET 0
#define CONFIG_TYPE_LOCAL 1
#define CONFIG_TYPE_REVERSE_PROXY 2

#ifndef DEFAULT_CONFIG_FILE
#   define DEFAULT_CONFIG_FILE "/etc/necronda/server.conf"
#endif


typedef struct {
    int type;
    char name[256];
    union {
        struct {
            char hostname[256];
            unsigned short port;
            unsigned char enc:1;
        } rev_proxy;
        struct {
            char webroot[256];
            unsigned char dir_mode:2;
        } local;
    };
} host_config;

extern host_config *config;
extern char cert_file[256], key_file[256], geoip_dir[256], dns_server[256];

int config_init();

int config_load(const char *filename);

int config_unload();

#endif //NECRONDA_SERVER_CONFIG_H
