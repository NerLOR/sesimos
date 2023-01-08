/**
 * sesimos - secure, simple, modern web server
 * @brief MaxMind GeoIP Database interface
 * @file src/lib/geoip.c
 * @author Lorenz Stechauner
 * @date 2021-05-04
 */

#include "geoip.h"
#include "../logger.h"
#include "error.h"
#include <memory.h>
#include <dirent.h>


static MMDB_s mmdbs[GEOIP_MAX_MMDB];

static MMDB_entry_data_list_s *geoip_json(MMDB_entry_data_list_s *list, char *str, long *str_off, long str_len) {
    switch (list->entry_data.type) {
        case MMDB_DATA_TYPE_MAP:
            *str_off += sprintf(str + *str_off, "{");
            break;
        case MMDB_DATA_TYPE_ARRAY:
            *str_off += sprintf(str + *str_off, "[");
            break;
        case MMDB_DATA_TYPE_UTF8_STRING:
            *str_off += sprintf(str + *str_off, "\"%.*s\"", list->entry_data.data_size, list->entry_data.utf8_string);
            break;
        case MMDB_DATA_TYPE_UINT16:
            *str_off += sprintf(str + *str_off, "%u", list->entry_data.uint16);
            break;
        case MMDB_DATA_TYPE_UINT32:
            *str_off += sprintf(str + *str_off, "%u", list->entry_data.uint32);
            break;
        case MMDB_DATA_TYPE_UINT64:
            *str_off += sprintf(str + *str_off, "%lu", list->entry_data.uint64);
            break;
        case MMDB_DATA_TYPE_UINT128:
            *str_off += sprintf(str + *str_off, "%llu", (unsigned long long) list->entry_data.uint128);
            break;
        case MMDB_DATA_TYPE_INT32:
            *str_off += sprintf(str + *str_off, "%i", list->entry_data.int32);
            break;
        case MMDB_DATA_TYPE_BOOLEAN:
            *str_off += sprintf(str + *str_off, "%s", list->entry_data.boolean ? "true" : "false");
            break;
        case MMDB_DATA_TYPE_FLOAT:
            *str_off += sprintf(str + *str_off, "%f", list->entry_data.float_value);
            break;
        case MMDB_DATA_TYPE_DOUBLE:
            *str_off += sprintf(str + *str_off, "%f", list->entry_data.double_value);
            break;
    }

    if (list->entry_data.type != MMDB_DATA_TYPE_MAP && list->entry_data.type != MMDB_DATA_TYPE_ARRAY)
        return list->next;

    MMDB_entry_data_list_s *next = list->next;
    int stat = 0;
    for (int i = 0; i < list->entry_data.data_size; i++) {
        next = geoip_json(next, str, str_off, str_len);
        if (list->entry_data.type == MMDB_DATA_TYPE_MAP) {
            stat = !stat;
            if (stat) {
                i--;
                *str_off += sprintf(str + *str_off, ":");
                continue;
            }
        }
        if (i != list->entry_data.data_size - 1)
            *str_off += sprintf(str + *str_off, ",");
    }

    *str_off += sprintf(str + *str_off, (list->entry_data.type == MMDB_DATA_TYPE_MAP) ? "}" : "]");

    return next;
}

int geoip_init(const char *directory) {
    char buf[512];

    memset(mmdbs, 0, sizeof(mmdbs));

    if (directory[0] == 0)
        return 0;

    DIR *geoip_dir;
    if ((geoip_dir = opendir(directory)) == NULL)
        return -1;

    struct dirent *entry;
    int i = 0, status;
    while ((entry = readdir(geoip_dir)) != NULL) {
        if (strcmp(entry->d_name + strlen(entry->d_name) - 5, ".mmdb") != 0)
            continue;

        if (i >= GEOIP_MAX_MMDB) {
            critical("Unable to initialize geoip: Too many .mmdb files");
            closedir(geoip_dir);
            return 1;
        }

        sprintf(buf, "%s/%s", directory, entry->d_name);
        if ((status = MMDB_open(buf, 0, &mmdbs[i])) != MMDB_SUCCESS) {
            error_mmdb(status);
            critical("Unable to initialize geoip: Unable to open .mmdb file");
            closedir(geoip_dir);
            return 1;
        }
        i++;
    }

    closedir(geoip_dir);

    if (i == 0) {
        critical("Unable to initialize geoip: No .mmdb files found in %s", directory);
        return 1;
    }

    return 0;
}

void geoip_free() {
    for (int i = 0; i < GEOIP_MAX_MMDB && mmdbs[i].file_content != NULL; i++) {
        MMDB_close(&mmdbs[i]);
    }
}

int geoip_lookup_country(struct sockaddr *addr, char *str) {
    for (int i = 0; i < GEOIP_MAX_MMDB && mmdbs[i].file_content != NULL; i++) {
        // lookup
        int mmdb_res;
        MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&mmdbs[i], addr, &mmdb_res);
        if (mmdb_res != MMDB_SUCCESS) {
            return -1;
        } else if (!result.found_entry) {
            continue;
        }

        // get country iso code
        MMDB_entry_data_s data;
        int status;
        if ((status = MMDB_get_value(&result.entry, &data, "country", "iso_code", NULL)) != MMDB_SUCCESS) {
            if (status == MMDB_IO_ERROR) {

            }
            return -1;
        }

        // no, or invalid data
        if (!data.has_data || data.type != MMDB_DATA_TYPE_UTF8_STRING)
            continue;

        // return country code
        sprintf(str, "%.2s", data.utf8_string);
        return 0;
    }

    // not found
    return 1;
}

int geoip_lookup_json(struct sockaddr *addr, char *json, long len) {
    long str_off = 0;
    for (int i = 0; i < GEOIP_MAX_MMDB && mmdbs[i].filename != NULL; i++) {
        int mmdb_res;
        MMDB_lookup_result_s result = MMDB_lookup_sockaddr(&mmdbs[i], addr, &mmdb_res);
        if (mmdb_res != MMDB_SUCCESS) {
            error_mmdb(mmdb_res);
            error("Unable to lookup geoip info");
            continue;
        } else if (!result.found_entry) {
            continue;
        }

        MMDB_entry_data_list_s *list;
        if ((mmdb_res = MMDB_get_entry_data_list(&result.entry, &list)) != MMDB_SUCCESS) {
            error_mmdb(mmdb_res);
            error("Unable to lookup geoip info");
            continue;
        }

        long prev = str_off;
        if (str_off != 0) {
            str_off--;
        }
        geoip_json(list, json, &str_off, len);
        if (prev != 0) {
            json[prev - 1] = ',';
        }

        MMDB_free_entry_data_list(list);
    }

    return 0;
}
