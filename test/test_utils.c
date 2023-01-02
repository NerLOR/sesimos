
#include <criterion/criterion.h>
#include <criterion/parameterized.h>

#include "../src/lib/utils.h"

struct url_encode_t {
    long in_size;
    char in[256];
    long exp_size;
    char exp[256];
};

struct format_duration_t {
    unsigned long micros;
    char exp[16];
};

ParameterizedTestParameters(utils, url_encode) {
    static struct url_encode_t params[] = {
            {0, "", 0, ""},
            {9, "Test Text", 11, "Test%20Text"},
            {21, "Text\0with\0null\0bytes\0", 29, "Text%00with%00null%00bytes%00"},
            {59, "Text&with+some/strange_symbols-or#something?I%don't|know...", 59, "Text&with+some/strange_symbols-or#something?I%don't|know..."},
            {33, "Data\x12With\x13Some" "\xFF" "Control" "\xFE" "Characters", 41, "Data%12With%13Some%FFControl%FECharacters"}
    };
    return cr_make_param_array(struct url_encode_t, params, sizeof(params) / sizeof(struct url_encode_t));
}

ParameterizedTest(struct url_encode_t *param, utils, url_encode) {
    char out[256];
    cr_assert_eq(url_encode(param->in, param->in_size, out, sizeof(out)), param->exp_size);
    cr_assert_arr_eq(out, param->exp, param->exp_size + 1);
}

Test(utils, url_encode_bytes) {
    char out[4];
    char exp[4];

    for (int i = 0; i < 256; i++) {
        unsigned char ch = i;
        if (ch <= 0x20 || ch >= 0x7F) {
            cr_assert_eq(url_encode(&ch, 1, out, sizeof(out)), 3);
            sprintf(exp, "%%%02X", ch);
            cr_assert_str_eq(out, exp);
        } else {
            cr_assert_eq(url_encode(&ch, 1, out, sizeof(out)), 1);
            sprintf(exp, "%c", ch);
            cr_assert_str_eq(out, exp);
        }
    }
}

Test(utils, url_encode_invalid) {
    cr_assert_eq(url_encode("Hello", 5, NULL, 0), 5);
}

ParameterizedTestParameters(utils, format_duration) {
    static struct format_duration_t params[] = {
            {0, "0.0 ms"},
            {1, "0.0 ms"},
            {90, "0.1 ms"},
            {100, "0.1 ms"},
            {110, "0.1 ms"},
            {900, "0.9 ms"},
            {1000, "1.0 ms"},
            {9000, "9.0 ms"},
            {9899, "9.9 ms"},
            {9999, "10.0 ms"},
            {10000, "10 ms"},
            {11999, "12 ms"},
            {999999, "1.0 s"},
            {1000000, "1.0 s"},
            {3000000, "3.0 s"},
            {1000000 * 60, "1:00 min"},
            {1000000 * 60 * 30L - 30000000, "29:30 min"},
            {1000000 * 60 * 60L, "60:00 min"},
            {1000000 * 60 * 120L, "120 min"},
    };
    return cr_make_param_array(struct format_duration_t, params, sizeof(params) / sizeof(struct format_duration_t));
}

ParameterizedTest(struct format_duration_t *param, utils, format_duration) {
    char buf[16];
    cr_assert_str_eq(format_duration(param->micros, buf), param->exp);
}
