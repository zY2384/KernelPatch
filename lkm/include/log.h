/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_LOG_H_
#define _KP_LKM_LOG_H_

#include <linux/printk.h>


//#define KP_LOG_ENABLE

#define KPLKM_TAG "kernelpatch-lkm"
#ifdef KP_LOG_ENABLE
#define logkem(fmt, ...) pr_emerg(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logki(fmt, ...) pr_info(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logke(fmt, ...) pr_err(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logkw(fmt, ...) pr_warn(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logkd(fmt, ...) pr_debug(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logkfi(fmt, ...) logki(fmt, ##__VA_ARGS__)
#define logkfe(fmt, ...) logke(fmt, ##__VA_ARGS__)
#define logkfd(fmt, ...) logkd(fmt, ##__VA_ARGS__)
#else
#define logkem(fmt, ...) no_printk(KPLKM_TAG ": " fmt, ##__VA_ARGS__)
#define logke(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define logkw(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define logkd(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define logkfi(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define logkfe(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#define logkfd(fmt, ...) no_printk(fmt, ##__VA_ARGS__)
#endif

#endif
