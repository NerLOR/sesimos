/**
 * Necronda Web Server
 * Utilities
 * src/utils.c
 * Lorenz Stechauner, 2020-12-03
 */

#include "utils.h"

char *format_duration(unsigned long micros, char *buf) {
    if (micros < 10000) {
        sprintf(buf, "%.1f ms", (double) micros / 1000);
    } else if (micros < 1000000) {
        sprintf(buf, "%li ms", micros / 1000);
    } else if (micros < 100000000) {
        sprintf(buf, "%.1f s", (double) micros / 1000000);
    } else if (micros < 6000000000) {
        sprintf(buf, "%.1f min", (double) micros / 1000000 / 60);
    } else {
        sprintf(buf, "%li min", micros / 1000000 / 60);
    }
    return buf;
}
