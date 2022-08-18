/**
 * sesimos - secure, simple, modern web server
 * Configuration file loader (header file)
 * src/lib/config.h
 * Lorenz Stechauner, 2021-01-05
 */

#ifndef SESIMOS_CONFIG_H
#define SESIMOS_CONFIG_H

#include "uri.h"

#define CONFIG_SHM_KEY 255642
#define CONFIG_MAX_HOST_CONFIG 64
#define CONFIG_MAX_CERT_CONFIG 64

#define CONFIG_TYPE_UNSET 0
#define CONFIG_TYPE_LOCAL 1
#define CONFIG_TYPE_REVERSE_PROXY 2

#ifndef DEFAULT_CONFIG_FILE
#   define DEFAULT_CONFIG_FILE "/etc/sesimos/sesimos.conf"
#endif


typedef struct {
    int type;
    char name[256];
    char cert_name[256];
    int cert;
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

typedef struct {
    char name[256];
    char full_chain[256];
    char priv_key[256];
} cert_config;

typedef struct {
    host_config hosts[CONFIG_MAX_HOST_CONFIG];
    cert_config certs[CONFIG_MAX_CERT_CONFIG];
} t_config;

extern t_config *config;
extern char geoip_dir[256], dns_server[256];

int config_init();

int config_load(const char *filename);

int config_unload();

#endif //SESIMOS_CONFIG_H
