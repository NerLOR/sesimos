/**
 * sesimos - secure, simple, modern web server
 * @brief MaxMind GeoIP Database interface
 * @file src/lib/geoip.c
 * @author Lorenz Stechauner
 * @date 2021-05-04
 */

#include "geoip.h"


MMDB_entry_data_list_s *mmdb_json(MMDB_entry_data_list_s *list, char *str, long *str_off, long str_len) {
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
            *str_off += sprintf(str + *str_off, "%i", list->entry_data.uint32);
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
    if (list->entry_data.type != MMDB_DATA_TYPE_MAP && list->entry_data.type != MMDB_DATA_TYPE_ARRAY) {
        return list->next;
    }
    MMDB_entry_data_list_s *next = list->next;
    int stat = 0;
    for (int i = 0; i < list->entry_data.data_size; i++) {
        next = mmdb_json(next, str, str_off, str_len);
        if (list->entry_data.type == MMDB_DATA_TYPE_MAP) {
            stat = !stat;
            if (stat) {
                i--;
                *str_off += sprintf(str + *str_off, ":");
                continue;
            }
        }
        if (i != list->entry_data.data_size - 1) *str_off += sprintf(str + *str_off, ",");
    }
    if (list->entry_data.type == MMDB_DATA_TYPE_MAP) {
        *str_off += sprintf(str + *str_off, "}");
    } else {
        *str_off += sprintf(str + *str_off, "]");
    }
    return next;
}
