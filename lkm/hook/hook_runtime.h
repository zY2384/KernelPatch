/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _KP_LKM_HOOK_RUNTIME_H_
#define _KP_LKM_HOOK_RUNTIME_H_

int kp_hook_runtime_init(void);

/* Check if @addr falls within any hook memory region allocated by hook_mem_zalloc().
 * Uses hash table for O(1) average lookup with precise size-based range checking. */
bool kp_hook_addr_in_region(unsigned long addr);

#endif
