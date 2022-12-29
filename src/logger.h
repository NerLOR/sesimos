/**
 * sesimos - secure, simple, modern web server
 * @brief Logger (header file)
 * @file src/logger.h
 * @author Lorenz Stechauner
 * @date 2022-12-10
 */

#ifndef SESIMOS_LOGGER_H
#define SESIMOS_LOGGER_H

#define LOG_DEBUG 7
#define LOG_INFO 6
#define LOG_NOTICE 5
#define LOG_WARNING 4
#define LOG_ERROR 3
#define LOG_CRITICAL 2
#define LOG_ALERT 1

typedef unsigned char log_lvl_t;

#define debug(...) logmsgf(LOG_DEBUG, __VA_ARGS__)
#define info(...) logmsgf(LOG_INFO, __VA_ARGS__)
#define notice(...) logmsgf(LOG_NOTICE, __VA_ARGS__)
#define warning(...) logmsgf(LOG_WARNING, __VA_ARGS__)
#define error(...) logmsgf(LOG_ERROR, __VA_ARGS__)
#define critical(...) logmsgf(LOG_CRITICAL, __VA_ARGS__)
#define alert(...) logmsgf(LOG_ALERT, __VA_ARGS__)

void logmsgf(log_lvl_t level, const char *restrict format, ...);

void logger_set_name(const char *restrict format, ...);

void logger_set_prefix(const char *restrict format, ...);

int logger_init(void);

void logger_stop(void);

#endif //SESIMOS_LOGGER_H
