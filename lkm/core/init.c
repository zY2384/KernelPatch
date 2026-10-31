// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2023 bmax121. All Rights Reserved.
 *
 * KernelPatch LKM entry. Loads via insmod, resolves symbols, scans for the
 * trusted APatch manager, and hooks syscall 45 as the supercall channel.
 */
#include <linux/module.h>
#include <linux/version.h>

#include "../include/kp_lkm.h"
#include "../infra/patch_memory.h"
#include "../infra/symbol_resolver.h"
#include "../infra/syscall_table.h"
#include "../hook/hook_runtime.h"
#include "../supercall/supercall.h"
#include "../kpm/module.h"
#include "../infra/secpass.h"
#include <linux/slab.h>

/*
 * Some A12-5.10 third-party kernels advertise CC_HAVE_STACKPROTECTOR_SYSREG but
 * don't provide __stack_chk_guard for modules; the DDK toolchain then generates
 * references to it. Manually provide it (same workaround as KernelSU).
 */
#if defined(CONFIG_STACKPROTECTOR) && defined(CONFIG_ARM64) && defined(MODULE) && \
    !defined(CONFIG_STACKPROTECTOR_PER_TASK)
#include <linux/random.h>
#include <linux/stackprotector.h>

unsigned long __stack_chk_guard __ro_after_init __attribute__((visibility("hidden")));

__attribute__((no_stack_protector)) void __init setup_stack_chk_guard(void)
{
	unsigned long canary;
	get_random_bytes(&canary, sizeof(canary));
	canary ^= LINUX_VERSION_CODE;
	canary &= CANARY_MASK;
	__stack_chk_guard = canary;
}

__attribute__((naked)) int __init kernelpatch_init_early(void)
{
	asm("mov x19, x30;"
	    "bl setup_stack_chk_guard;"
	    "mov x30, x19;"
	    "b kernelpatch_init;");
}
#define NEED_OWN_STACKPROTECTOR 1
#else
#define NEED_OWN_STACKPROTECTOR 0
#endif


unsigned char hello_kpm_data[] = {
  0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x01, 00, 0xb7, 00, 0x01, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x40, 0x05, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x40, 00, 00, 00, 00, 00, 0x40, 00,  0x0e, 00, 0x0c, 00, 0xfd, 0x7b, 0xbf, 0xa9, 0x08, 00, 00, 0x90,  00, 00, 00, 0x90, 00, 00, 00, 0x91, 0x08, 0x01, 0x40, 0xf9,  0xfd, 0x03, 00, 0x91, 00, 0x01, 0x3f, 0xd6, 0xe0, 0x03, 0x1f, 0xaa,  0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6, 0xfd, 0x7b, 0xbf, 0xa9,  0x08, 00, 00, 0x90, 0xe1, 0x03, 00, 0xaa, 00, 00, 00, 0x90,  00, 00, 00, 0x91, 0x08, 0x01, 0x40, 0xf9, 0xfd, 0x03, 00, 0x91,  00, 0x01, 0x3f, 0xd6, 0xe0, 0x03, 0x1f, 0xaa, 0xfd, 0x7b, 0xc1, 0xa8,  0xc0, 0x03, 0x5f, 0xd6, 0x08, 00, 00, 0x90, 00, 00, 00, 0x90,  00, 00, 00, 0x91, 0x01, 0x01, 0x40, 0xf9, 0x20, 00, 0x1f, 0xd6,  0x6e, 0x61, 0x6d, 0x65, 0x3d, 0x6b, 0x70, 0x61, 0x74, 0x63, 0x68, 0x2d,  0x68, 0x65, 0x6c, 0x6c, 0x6f, 00, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f,  0x6e, 0x3d, 0x30, 0x2e, 0x31, 0x33, 0x2e, 0x39, 0x2e, 0x31, 0x30, 0x30,  00, 0x6c, 0x69, 0x63, 0x65, 0x6e, 0x73, 0x65, 0x3d, 0x47, 0x50, 0x4c,  0x20, 0x76, 0x32, 00, 0x61, 0x75, 0x74, 0x68, 0x6f, 0x72, 0x3d, 0x4b,  0x69, 0x6e, 0x67, 0x37, 0x37, 0x37, 00, 0x64, 0x65, 0x73, 0x63, 0x72,  0x69, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x3d, 0xe5, 0x88, 0x9b, 0xe5, 0xbb,  0xba, 0xe8, 0xbe, 0x83, 0xe4, 0xb8, 0xba, 0xe5, 0xae, 0x8c, 0xe6, 0x95,  0xb4, 0xe7, 0x9a, 0x84, 0x4b, 0x65, 0x72, 0x6e, 0x65, 0x6c, 0x50, 0x61,  0x74, 0x63, 0x68, 0xe7, 0x8e, 0xaf, 0xe5, 0xa2, 0x83, 0xe7, 0x94, 0xa8,  0xe4, 0xba, 0x8e, 0xe5, 0x8a, 0xa0, 0xe8, 0xbd, 0xbd, 0x6b, 0x70, 0x6d,  0xef, 0xbc, 0x8c, 0xe5, 0xb9, 0xb6, 0xe5, 0xb0, 0x86, 0x5f, 0x5f, 0x4e,  0x52, 0x5f, 0x73, 0x75, 0x70, 0x65, 0x72, 0x63, 0x61, 0x6c, 0x6c, 0xe6,  0x8c, 0x82, 0xe5, 0x88, 0xb0, 0x69, 0x6e, 0x76, 0x6f, 0x6b, 0x65, 0x5f,  0x73, 0x79, 0x73, 0x63, 0x61, 0x6c, 0x6c, 0x2f, 0x65, 0x6c, 0x30, 0x5f,  0x73, 0x76, 0x63, 0x5f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0xe4, 0xb8,  0x8a, 0xef, 0xbc, 0x8c, 0xe5, 0x90, 0x8c, 0xe6, 0x97, 0xb6, 0xe5, 0x8f,  0xaa, 0xe6, 0x9c, 0x89, 0x72, 0x6f, 0x6f, 0x74, 0xe6, 0x89, 0x8d, 0xe8,  0x83, 0xbd, 0xe8, 0xae, 0xbf, 0xe9, 0x97, 0xae, 0xe5, 0xae, 0x83, 0x2e,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x01, 0x36, 0x6b, 0x70, 0x6d, 0x20, 0x70, 0x61,  0x74, 0x63, 0x68, 0x5f, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x30,  0x2c, 0x20, 0x61, 0x72, 0x67, 0x73, 0x3a, 0x20, 0x25, 0x73, 0x0a, 00,  0x01, 0x36, 0x6b, 0x70, 0x6d, 0x20, 0x70, 0x61, 0x74, 0x63, 0x68, 0x5f,  0x65, 0x78, 0x69, 0x74, 0x0a, 00, 0x01, 0x36, 0x6b, 0x70, 0x6d, 0x20,  0x70, 0x61, 0x74, 0x63, 0x68, 0x5f, 0x69, 0x6e, 0x69, 0x74, 0x0a, 00,  00, 00, 00, 00, 0x04, 00, 00, 00, 00, 00, 00, 00,  0x13, 0x01, 00, 00, 0x0d, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x08, 00, 00, 00, 00, 00, 00, 00,  0x13, 0x01, 00, 00, 0x0c, 00, 00, 00, 0x32, 00, 00, 00,  00, 00, 00, 00, 0x0c, 00, 00, 00, 00, 00, 00, 00,  0x15, 0x01, 00, 00, 0x0c, 00, 00, 00, 0x32, 00, 00, 00,  00, 00, 00, 00, 0x10, 00, 00, 00, 00, 00, 00, 00,  0x1e, 0x01, 00, 00, 0x0d, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x2c, 00, 00, 00, 00, 00, 00, 00,  0x13, 0x01, 00, 00, 0x0d, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x34, 00, 00, 00, 00, 00, 00, 00,  0x13, 0x01, 00, 00, 0x0c, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x38, 00, 00, 00, 00, 00, 00, 00,  0x15, 0x01, 00, 00, 0x0c, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x3c, 00, 00, 00, 00, 00, 00, 00,  0x1e, 0x01, 00, 00, 0x0d, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x54, 00, 00, 00, 00, 00, 00, 00,  0x13, 0x01, 00, 00, 0x0d, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x58, 00, 00, 00, 00, 00, 00, 00,  0x13, 0x01, 00, 00, 0x0c, 00, 00, 00, 0x20, 00, 00, 00,  00, 00, 00, 00, 0x5c, 00, 00, 00, 00, 00, 00, 00,  0x15, 0x01, 00, 00, 0x0c, 00, 00, 00, 0x20, 00, 00, 00,  00, 00, 00, 00, 0x60, 00, 00, 00, 00, 00, 00, 00,  0x1e, 0x01, 00, 00, 0x0d, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0x01, 0x01, 00, 00, 0x07, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0x01, 0x01, 00, 00, 0x07, 00, 00, 00, 0x28, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0x01, 0x01, 00, 00, 0x07, 00, 00, 00, 0x54, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x21, 00, 00, 00, 00, 00, 0x01, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x1c, 00, 00, 00, 00, 00, 0x03, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x17, 00, 00, 00, 00, 00, 0x04, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x12, 00, 00, 00, 00, 00, 0x06, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x0d, 00, 00, 00, 00, 00, 0x08, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x08, 00, 00, 00, 00, 00, 0x0a, 00,  0x32, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x03, 00, 0x01, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x03, 00, 0x03, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x03, 00, 0x04, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x03, 00, 0x06, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x03, 00, 0x08, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x03, 00, 0x0a, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x01, 00, 00, 00, 0x10, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 0x2e, 0x72, 0x65, 0x6c, 0x61, 0x2e, 0x74,  0x65, 0x78, 0x74, 00, 0x2e, 0x72, 0x65, 0x6c, 0x61, 0x2e, 0x6b, 0x70,  0x6d, 0x2e, 0x65, 0x78, 0x69, 0x74, 00, 0x2e, 0x72, 0x65, 0x6c, 0x61,  0x2e, 0x6b, 0x70, 0x6d, 0x2e, 0x69, 0x6e, 0x69, 0x74, 00, 0x2e, 0x6b,  0x70, 0x6d, 0x2e, 0x69, 0x6e, 0x66, 0x6f, 00, 0x2e, 0x73, 0x68, 0x73,  0x74, 0x72, 0x74, 0x61, 0x62, 00, 0x2e, 0x73, 0x74, 0x72, 0x74, 0x61,  0x62, 00, 0x2e, 0x73, 0x79, 0x6d, 0x74, 0x61, 0x62, 00, 0x2e, 0x72,  0x6f, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x73, 0x74, 0x72, 0x31, 0x2e, 0x31,  00, 0x2e, 0x72, 0x65, 0x6c, 0x61, 0x2e, 0x6b, 0x70, 0x6d, 0x2e, 0x63,  0x74, 0x6c, 0x30, 00, 00, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x6b, 00,  0x24, 0x64, 0x2e, 0x35, 00, 0x24, 0x64, 0x2e, 0x34, 00, 0x24, 0x64,  0x2e, 0x33, 00, 0x24, 0x64, 0x2e, 0x32, 00, 0x24, 0x64, 0x2e, 0x31,  00, 0x24, 0x78, 0x2e, 0x30, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x06, 00, 00, 00, 0x01, 00, 00, 00,  0x06, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x40, 00, 00, 00, 00, 00, 00, 00,  0x68, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x04, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x01, 00, 00, 00,  0x04, 00, 00, 00, 0x40, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0xf0, 0x01, 00, 00,  00, 00, 00, 00, 0x20, 0x01, 00, 00, 00, 00, 00, 00,  0x0b, 00, 00, 00, 0x01, 00, 00, 00, 0x08, 00, 00, 00,  00, 00, 00, 00, 0x18, 00, 00, 00, 00, 00, 00, 00,  0x2a, 00, 00, 00, 0x01, 00, 00, 00, 0x02, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0xa8, 00, 00, 00, 00, 00, 00, 00, 0xe5, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0x01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x20, 00, 00, 00, 0x01, 00, 00, 00,  0x03, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x90, 0x01, 00, 00, 00, 00, 00, 00,  0x08, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x08, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x1b, 00, 00, 00,  0x04, 00, 00, 00, 0x40, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x10, 0x03, 00, 00,  00, 00, 00, 00, 0x18, 00, 00, 00, 00, 00, 00, 00,  0x0b, 00, 00, 00, 0x04, 00, 00, 00, 0x08, 00, 00, 00,  00, 00, 00, 00, 0x18, 00, 00, 00, 00, 00, 00, 00,  0x62, 00, 00, 00, 0x01, 00, 00, 00, 0x03, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0x98, 0x01, 00, 00, 00, 00, 00, 00, 0x08, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0x08, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x5d, 00, 00, 00, 0x04, 00, 00, 00,  0x40, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x28, 0x03, 00, 00, 00, 00, 00, 00,  0x18, 00, 00, 00, 00, 00, 00, 00, 0x0b, 00, 00, 00,  0x06, 00, 00, 00, 0x08, 00, 00, 00, 00, 00, 00, 00,  0x18, 00, 00, 00, 00, 00, 00, 00, 0x11, 00, 00, 00,  0x01, 00, 00, 00, 0x03, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0xa0, 0x01, 00, 00,  00, 00, 00, 00, 0x08, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x08, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0x0c, 00, 00, 00, 0x04, 00, 00, 00, 0x40, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0x40, 0x03, 00, 00, 00, 00, 00, 00, 0x18, 00, 00, 00,  00, 00, 00, 00, 0x0b, 00, 00, 00, 0x08, 00, 00, 00,  0x08, 00, 00, 00, 00, 00, 00, 00, 0x18, 00, 00, 00,  00, 00, 00, 00, 0x4e, 00, 00, 00, 0x01, 00, 00, 00,  0x32, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0xa8, 0x01, 00, 00, 00, 00, 00, 00,  0x44, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x01, 00, 00, 00, 00, 00, 00, 00,  0x01, 00, 00, 00, 00, 00, 00, 00, 0x46, 00, 00, 00,  0x02, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 0x58, 0x03, 00, 00,  00, 00, 00, 00, 0x50, 0x01, 00, 00, 00, 00, 00, 00,  0x0d, 00, 00, 00, 0x0d, 00, 00, 00, 0x08, 00, 00, 00,  00, 00, 00, 00, 0x18, 00, 00, 00, 00, 00, 00, 00,  0x34, 00, 00, 00, 0x03, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0xa8, 0x04, 00, 00, 00, 00, 00, 00, 0x6c, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  0x01, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x3e, 00, 00, 00, 0x03, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x14, 0x05, 00, 00, 00, 00, 00, 00,  0x26, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 0x01, 00, 00, 00, 00, 00, 00, 00,  00, 00, 00, 00, 00, 00, 00, 00
};

int __init kernelpatch_init(void)
{
	int rc;

	logki("KernelPatch LKM loading (version %x, kernel %x)\n", kpver, (unsigned)LINUX_VERSION_CODE);

	kp_symres_init();

	rc = kp_syscall_table_init();
	if (rc)
		return rc;

	rc = kp_patch_memory_init();
	if (rc)
		return rc;

	rc = kp_hook_runtime_init();
	if (rc)
		/* No executable-memory path for hook trampolines (set_memory_x and
		 * execmem_alloc both missing). Continuing would call a NULL allocator
		 * and crash the kernel; fail the load cleanly instead. */
		return rc;

	rc = kp_bypass_kcfi();
	if (rc)
		logkw("CFI bypass failed: %d\n", rc);

	rc = kp_kpm_init();
	if (rc)
		logkw("kpm loader init failed: %d (KPM supercalls will return -ENOSYS)\n", rc);

	//rc = kp_supercall_install();
	//char *path = (char *)kzalloc(1024, GFP_KERNEL);
	//strcpy(path, "/data/adb/kpatch-hello.kpm");
	
	//rc = (int)kp_load_module_path(path, NULL, NULL);
	rc = (int)kp_load_module(hello_kpm_data, sizeof(hello_kpm_data), NULL, "load-file", NULL);
	if (rc)
	{
		logkw("kpm kp_load_module_path failed: %d\n", rc);
		return rc;
	}

	logki("KernelPatch LKM ready\n");
	
	kobject_del(&THIS_MODULE->mkobj.kobj);
	
	return 0;
}

static void __exit kernelpatch_exit(void)
{
	//kp_supercall_uninstall();
	/* Unhook the CFI bypass last so it shields the other teardown from
	 * spurious CFI failures on LKM/KPM text. */
	kp_bypass_kcfi_exit();
	logki("KernelPatch LKM unloaded\n");
}

#if NEED_OWN_STACKPROTECTOR
module_init(kernelpatch_init_early);
#else
module_init(kernelpatch_init);
#endif
module_exit(kernelpatch_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("bmax121");
MODULE_DESCRIPTION("KernelPatch LKM THIRD-PARTY");
MODULE_VERSION(KP_LKM_VERSION_STRING);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
MODULE_IMPORT_NS("VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver");
#else
MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver);
#endif
