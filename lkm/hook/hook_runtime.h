/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_HOOK_RUNTIME_H_
#define _KP_LKM_HOOK_RUNTIME_H_

int kp_hook_runtime_init(void);

/* True if @addr lies in a hook trampoline page allocated by hook_mem_zalloc(). */
bool kp_hook_runtime_contains_addr(unsigned long addr);

#endif
