// SPDX-License-Identifier: GPL-2.0-or-later
/* Reuse KernelPatch's ARM64 relocation and hook-chain engine. */
#include <linux/compiler.h>
#include <linux/types.h>

#ifndef __noinline
#define __noinline noinline
#endif

/*
 * The original kpimg linker script provides _transit*_end symbols so each
 * transit function can be byte-copied into hook memory, preserving the PC-
 * relative "LDR X16, #12" self-referencing chain pointer read.
 *
 * Linux modules have no such linker markers.  Instead of branching to the
 * resident LKM _transitN (which would resolve its PC-relative offset inside
 * the module's .text rather than the chain object), we copy the transit code
 * into the chain's transit[] slot so the same PC-relative math works.
 *
 * Because we cannot compute _transitN_end at link time, we use a conservative
 * maximum instruction count (TRANSIT_INST_NUM = 0x70) and rely on the fact
 * that the source transit functions in hook.c are well under that bound.
 * The copy is safe: the tail bytes beyond the real function end are never
 * reached because the B #16 jumps straight into the copied body.
 */
#define KP_HOOK_EXTERNAL_CHAIN_PREPARE

#include "../../kernel/base/hook.c"

static hook_err_t hook_chain_prepare(uint32_t *transit, int32_t argno)
{
	hook_chain_t *chain = local_container_of(transit, hook_chain_t, transit);
	uint32_t *src;

	if (argno < 0 || argno > 12)
		return -HOOK_BAD_ADDRESS;

	/* Pick the source transit function to copy. */
	switch (argno) {
	case 0:  src = (uint32_t *)&_transit0; break;
	case 1:
	case 2:
	case 3:
	case 4:  src = (uint32_t *)&_transit4; break;
	case 5:
	case 6:
	case 7:
	case 8:  src = (uint32_t *)&_transit8; break;
	default: src = (uint32_t *)&_transit12; break;
	}

	/* Write the header first (same order as kpimg mode). */
	transit[0] = ARM64_BTI_JC;
	transit[1] = 0x58000070; /* LDR X16, #12 */
	transit[2] = 0x14000004; /* B #16 — jumps past the 6-header words into the copied body */
	transit[3] = ARM64_NOP;
	transit[4] = (uint64_t)chain & 0xFFFFFFFF;
	transit[5] = (uint64_t)chain >> 32;

	/*
	 * Copy the transit function body into the chain's transit[] slot,
	 * starting at transit[6].  We copy TRANSIT_INST_NUM instructions
	 * (the maximum the slot can hold); the actual function is much
	 * shorter so the excess is harmless.
	 */
	for (int i = 0; i < TRANSIT_INST_NUM; i++)
		transit[i + 6] = src[i];

	return HOOK_NO_ERR;
}
