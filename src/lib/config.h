/**
 * sesimos - secure, simple, modern web server
 * @brief Configuration file loader (header file)
 * @file src/lib/config.h
 * @author Lorenz Stechauner
 * @date 2021-01-05
 */

#ifndef SESIMOS_CONFIG_H
#define SESIMOS_CONFIG_H

#include "uri.h"
#include "../cache_handler.h"

#define CONFIG_MAX_HOST_CONFIG 64
#define CONFIG_MAX_CERT_CONFIG 64

#define CONFIG_TYPE_UNSET 0
#define CONFIG_TYPE_LOCAL 1
#define CONFIG_TYPE_REVERSE_PROXY 2

#ifndef DEFAULT_CONFIG_FILE
#   define DEFAULT_CONFIG_FILE "/etc/sesimos/server.conf"
#endif


typedef struct {
    int type;
    char name[256];
    char cert_name[256];
    int cert;
    cache_t *cache;
    union {
        struct {
            char hostname[256];
            unsigned short port;
            unsigned char enc:1;
        } proxy;
        struct {
            char webroot[256];
            unsigned char dir_mode:2;
        } local;
    };
} host_config_t;

typedef struct {
    char name[256];
    char full_chain[256];
    char priv_key[256];
} cert_config_t;

typedef struct {
    host_config_t hosts[CONFIG_MAX_HOST_CONFIG];
    cert_config_t certs[CONFIG_MAX_CERT_CONFIG];
    char geoip_dir[256];
    char dns_server[256];
} config_t;

extern config_t config;

int config_load(const char *filename);

host_config_t *get_host_config(const char *host);

#endif //SESIMOS_CONFIG_H
