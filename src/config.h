/**
 * Necronda Web Server
 * Configuration file loader (header file)
 * src/config.h
 * Lorenz Stechauner, 2021-01-05
 */


#ifndef NECRONDA_SERVER_CONFIG_H
#define NECRONDA_SERVER_CONFIG_H

typedef struct {
    int type;
    char name[256];
    union {
        struct {
            char address[256];
            unsigned short port;
        };
        struct {
            char webroot[256];
            unsigned char dir_mode;
        };
    };
} host_config;


int config_init();

int config_load();

#endif //NECRONDA_SERVER_CONFIG_H
