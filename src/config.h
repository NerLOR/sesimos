/**
 * Necronda Web Server
 * Configuration file loader (header file)
 * src/config.h
 * Lorenz Stechauner, 2021-01-05
 */


#ifndef NECRONDA_SERVER_CONFIG_H
#define NECRONDA_SERVER_CONFIG_H

#define CONFIG_TYPE_UNSET 0
#define CONFIG_TYPE_LOCAL 1
#define CONFIG_TYPE_REVERSE_PROXY 2


typedef struct {
    int type;
    char name[256];
    union {
        struct {
            char hostname[256];
            unsigned short port;
        } rev_proxy;
        struct {
            char webroot[256];
            unsigned char dir_mode;
        } local;
    };
} host_config;


host_config *config;
char cert_file[256], key_file[256], geoip_dir[256], dns_server[256];


int config_init();

int config_load(const char *filename);

int config_unload();

#endif //NECRONDA_SERVER_CONFIG_H
