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

extern const char _binary_bin_res_default_txt_start[];
extern const char _binary_bin_res_default_txt_end[];

extern const char _binary_bin_res_proxy_txt_start[];
extern const char _binary_bin_res_proxy_txt_end[];

extern const char _binary_bin_res_style_txt_start[];
extern const char _binary_bin_res_style_txt_end[];

#endif //SESIMOS_RES_H
