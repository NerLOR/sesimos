/**
 * sesimos - secure, simple, modern web server
 * @brief HTTP resources (header file)
 * @file src/lib/res.h
 * @author Lorenz Stechauner
 * @date 2022-12-31
 */

#ifndef SESIMOS_RES_H
#define SESIMOS_RES_H

#define http_default_doc        _binary_bin_res_default_txt_start
#define http_default_doc_size   ((unsigned int) (_binary_bin_res_default_txt_end - _binary_bin_res_default_txt_start) - 1)
#define http_proxy_doc          _binary_bin_res_proxy_txt_start
#define http_proxy_doc_size     ((unsigned int) (_binary_bin_res_proxy_txt_end - _binary_bin_res_proxy_txt_start) - 1)
#define http_style_doc          _binary_bin_res_style_txt_start
#define http_style_doc_size     ((unsigned int) (_binary_bin_res_style_txt_end - _binary_bin_res_style_txt_start) - 1)

#define http_icon_error         _binary_bin_res_icon_error_txt_start
#define http_icon_error_size    ((unsigned int) (_binary_bin_res_icon_error_txt_end - _binary_bin_res_icon_error_txt_start) - 1)
#define http_icon_info          _binary_bin_res_icon_info_txt_start
#define http_icon_info_size     ((unsigned int) (_binary_bin_res_icon_info_txt_end - _binary_bin_res_icon_info_txt_start) - 1)
#define http_icon_success       _binary_bin_res_icon_success_txt_start
#define http_icon_success_size  ((unsigned int) (_binary_bin_res_icon_success_txt_end - _binary_bin_res_icon_success_txt_start) - 1)
#define http_icon_warning       _binary_bin_res_icon_warning_txt_start
#define http_icon_warning_size  ((unsigned int) (_binary_bin_res_icon_warning_txt_end - _binary_bin_res_icon_warning_txt_start) - 1)

typedef struct {
    const char *name;
    const char *type;
    const char *content;
    const unsigned int size;
} res_t;

extern const char _binary_bin_res_default_txt_start[];
extern const char _binary_bin_res_default_txt_end[];

extern const char _binary_bin_res_proxy_txt_start[];
extern const char _binary_bin_res_proxy_txt_end[];

extern const char _binary_bin_res_style_txt_start[];
extern const char _binary_bin_res_style_txt_end[];

extern const char _binary_bin_res_icon_error_txt_start[];
extern const char _binary_bin_res_icon_error_txt_end[];

extern const char _binary_bin_res_icon_info_txt_start[];
extern const char _binary_bin_res_icon_info_txt_end[];

extern const char _binary_bin_res_icon_success_txt_start[];
extern const char _binary_bin_res_icon_success_txt_end[];

extern const char _binary_bin_res_icon_warning_txt_start[];
extern const char _binary_bin_res_icon_warning_txt_end[];

#endif //SESIMOS_RES_H
