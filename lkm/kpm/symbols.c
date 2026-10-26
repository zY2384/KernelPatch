// SPDX-License-Identifier: GPL-2.0-or-later
/* Compatibility symbols exported by the in-kernel KP runtime to KPMs. */
#include "symbols.h"

#include <linux/cred.h>
#include <linux/gfp.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
#include <linux/stdarg.h>
#else
/* linux/stdarg.h is absent before 5.14; the repo's kernel/include/stdarg.h
 * (found via -I) provides the same __builtin_va_* wrappers. */
#include <stdarg.h>
#endif
#include "../include/kp_lkm.h"
#include "../infra/symbol_resolver.h"
#include "../infra/patch_memory.h"
#include "../infra/syscall_table.h"
#include "module.h"

#include <asm/thread_info.h>
#include <hook.h>
#include <linux/spinlock.h>
#include <asm/ptrace.h>

static u32 kp_kpm_kver = LINUX_VERSION_CODE;
static u32 kp_kpm_kpver = KP_LKM_VERSION_CODE;
static int kp_kpm_thread_size = THREAD_SIZE;
static int kp_kpm_thread_info_in_task = 1;
static int kp_kpm_sp_el0_is_current = 1;
static int kp_kpm_sp_el0_is_thread_info;
static int kp_kpm_task_in_thread_info_offset = -1;
/* KP ABI stack-layout facts (arm64 GKI: task->stack + THREAD_SIZE is the end
 * of stack, pt_regs sits just below it). */
static int kp_kpm_stack_in_task_offset = offsetof(struct task_struct, stack);
static int kp_kpm_stack_end_offset = THREAD_SIZE;
static int kp_kpm_has_syscall_wrapper;


/* ===== 全局调度器核心结构 ===== */

#define SYSCALL_HOOK_SLOT_NUM 64
#define SYSCALL_HOOK_MAX_MATCH 16

typedef void (*syscall_hook_cb_t)(void *fargs, void *udata);
typedef int (*syscall_hook_gate_t)(void);

typedef struct {
    int32_t nr;          // syscall 号
    int32_t is_compat;   // 0=native, 1=compat32
    void *before;        // before 回调 (hook_fargs8_callback)
    void *after;         // after 回调
    void *udata;         // 用户数据
    int8_t allow_skip;   // 是否允许 skip_origin
    int8_t bypass_gate;  // 是否绕过 uid gate
    volatile int8_t state; // EMPTY / BUSY / READY
} syscall_hook_slot_t;

static syscall_hook_slot_t syscall_hooks[SYSCALL_HOOK_SLOT_NUM];
static volatile int syscall_hook_high = 0;      // 高水位
static volatile int syscall_hook_global = 0;     // 全局调度器已启用
static volatile int syscall_hook_handler_granular = 0;  // 是否挂在 invoke_syscall
static syscall_hook_gate_t syscall_hook_gate = 0;
//static spinlock_t syscall_hook_lock;  /* LKM: 换成 kernel mutex 或 spinlock */
static DEFINE_RAW_SPINLOCK(syscall_hook_lock);
struct syscall_hook_snapshot
{
    syscall_hook_cb_t before;
    syscall_hook_cb_t after;
    void *udata;
    int8_t allow_skip;
};


/* 以下在 kpimg 中已定义，LKM 需提供等价物： */

/* 已有: sys_call_table, compat_sys_call_table, has_syscall_wrapper, has_config_compat */

/* LKM 替代 kallsyms_lookup_name_by_suffix: */
static inline unsigned long kallsyms_lookup_name_by_suffix(const char *name)
{
    return (unsigned long)kp_resolve_symbol_variant(name);
}

/* LKM 替代 kp_private_spin_lock/unlock: */
static inline unsigned long kp_private_spin_lock(raw_spinlock_t *lock)
{
    unsigned long flags;
    raw_spin_lock_irqsave(lock, flags);
    return flags;
}
static inline void kp_private_spin_unlock(raw_spinlock_t *lock, unsigned long flags)
{
    raw_spin_unlock_irqrestore(lock, flags);
}

/* 内联 barrier */
static inline void syscall_hook_barrier(void)
{
    asm volatile("dsb ish" ::: "memory");
}

/* nr 解析: scno 是 arg1 of el0_svc_common; 若内核 scno 参数缺失，回退到 regs->regs[] */
static long syscall_dispatch_nr(struct pt_regs *regs, unsigned long scno, int is_compat)
{
    long nr = (long)scno;
    if (nr < 0 || nr >= 1024)
        nr = (long)(is_compat ? regs->regs[7] : regs->regs[8]);
    return nr;
}

static int syscall_hook_collect(int nr, int is_compat, int gate_ok, struct syscall_hook_snapshot *out, int max)
{
    int n = 0;
    int high = syscall_hook_high;
    if (high > SYSCALL_HOOK_SLOT_NUM) high = SYSCALL_HOOK_SLOT_NUM;

    for (int i = 0; i < high; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_READY) continue;
        if (syscall_hooks[i].nr != nr || syscall_hooks[i].is_compat != is_compat) continue;
        if (!gate_ok && !syscall_hooks[i].bypass_gate) continue;
        if (n >= max) break;
        out[n].before = (syscall_hook_cb_t)syscall_hooks[i].before;
        out[n].after = (syscall_hook_cb_t)syscall_hooks[i].after;
        out[n].udata = syscall_hooks[i].udata;
        out[n].allow_skip = syscall_hooks[i].allow_skip;
        n++;
    }
    return n;
}

static void syscall_dispatch_before(hook_fargs8_t *args, void *udata)
{
    (void)udata;
    struct pt_regs *regs = (struct pt_regs *)args->arg0;
    if (!regs) return;

    int is_compat = compat_user_mode(regs) ? 1 : 0;
    long nr = syscall_dispatch_nr(regs, args->arg1, is_compat);

    if (!syscall_hook_high) return;

    /* One uid gate, evaluated once per syscall for every callback, instead of a
     * root check inside each callback. For a process that is not su-authorized
     * nothing is dispatched, so behavior and cost are the same across all
     * syscalls: no per-syscall fingerprint, and fstatat/statx/... cannot
     * disagree. Slots registered with bypass_gate (the magic supercall, which
     * authenticates with its own key) still run. */
    int gate_ok = 1;
    if (syscall_hook_gate) gate_ok = syscall_hook_gate() ? 1 : 0;

    struct syscall_hook_snapshot snap[SYSCALL_HOOK_MAX_MATCH];
    int n = syscall_hook_collect((int)nr, is_compat, gate_ok, snap, SYSCALL_HOOK_MAX_MATCH);
    if (!n) return;

    /* Hooked at invoke_syscall (handler granularity) el0_svc_common has already
     * set these; hooked at its entry we must set them ourselves so callbacks
     * that inspect them (resolve_pt_regs scans the stack for a matching frame)
     * see the same state as under the per-syscall hook. */
    if (!syscall_hook_handler_granular) {
        regs->orig_x0 = regs->regs[0];
        regs->syscallno = nr;
    }

    /* arg1..arg3 are scno/sc_nr/table, not syscall arguments; they must reach the
     * origin unchanged for it to pick the right handler. */
    uint64_t keep_arg1 = args->arg1;
    uint64_t keep_arg2 = args->arg2;
    uint64_t keep_arg3 = args->arg3;

    args->skip_origin = 0;
    args->ret = 0;

    int can_skip = 0;
    for (int i = 0; i < n; i++) {
        if (snap[i].allow_skip) can_skip = 1;
        if (snap[i].before) snap[i].before(args, snap[i].udata);
    }

    args->arg1 = keep_arg1;
    args->arg2 = keep_arg2;
    args->arg3 = keep_arg3;

    /* Honour skip_origin only where it means "skip this one syscall's handler".
     * At invoke_syscall granularity el0_svc_common still runs syscall_trace_enter
     * and syscall_trace_exit around it, so the overridden result has to be placed
     * in regs->regs[0] here. When hooked at el0_svc_common's entry, skip_origin
     * would skip that whole function (tracing, exit work and all), so it is
     * refused unless the caller explicitly opted in. */
    if (args->skip_origin && can_skip && syscall_hook_handler_granular) {
        regs->regs[0] = args->ret;
    } else {
        args->skip_origin = 0;
    }
}

static void syscall_dispatch_after(hook_fargs8_t *args, void *udata)
{
    (void)udata;
    struct pt_regs *regs = (struct pt_regs *)args->arg0;
    if (!regs) return;

    int is_compat = compat_user_mode(regs) ? 1 : 0;
    /* Use the scno captured by the transit at function entry, not regs->syscallno:
     * el0_svc_common only assigns syscallno for in-range syscalls, so an invalid
     * number would leave the previous syscall's value there and we would run the
     * wrong afters. args->arg1 is the original scno; callbacks that rewrite a
     * syscall argument go through set_syscall_argn(), which touches regs->regs[],
     * not this copy. */
    long nr = syscall_dispatch_nr(regs, args->arg1, is_compat);

    if (!syscall_hook_high) return;

    /* Same gate as the before phase: an after callback must never run without
     * its before callback having run. */
    int gate_ok = 1;
    if (syscall_hook_gate) gate_ok = syscall_hook_gate() ? 1 : 0;

    struct syscall_hook_snapshot snap[SYSCALL_HOOK_MAX_MATCH];
    int n = syscall_hook_collect((int)nr, is_compat, gate_ok, snap, SYSCALL_HOOK_MAX_MATCH);
    if (!n) return;

    /* The real return value lives in regs->regs[0]; el0_svc_common returns void,
     * so mirror it into fargs->ret for the after callbacks and copy any change
     * back, matching the fp-hook chain semantics. */
    args->ret = regs->regs[0];
    for (int i = n - 1; i >= 0; i--) {
        if (snap[i].after) snap[i].after(args, snap[i].udata);
    }
    regs->regs[0] = args->ret;
}

static hook_err_t syscall_hook_add(int nr, int is_compat, void *before, void *after, void *udata, int allow_skip,
                                   int bypass_gate)
{
    unsigned long flags = kp_private_spin_lock(&syscall_hook_lock);
    int i;
    for (i = 0; i < SYSCALL_HOOK_SLOT_NUM; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_READY) continue;
        if (syscall_hooks[i].nr != nr || syscall_hooks[i].is_compat != is_compat) continue;
        if ((before && syscall_hooks[i].before == before) || (after && syscall_hooks[i].after == after)) {
            kp_private_spin_unlock(&syscall_hook_lock, flags);
            return -HOOK_DUPLICATED;
        }
    }

    for (i = 0; i < SYSCALL_HOOK_SLOT_NUM; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_EMPTY) continue;
        syscall_hooks[i].state = CHAIN_ITEM_STATE_BUSY;
        syscall_hook_barrier();
        syscall_hooks[i].nr = nr;
        syscall_hooks[i].is_compat = is_compat;
        syscall_hooks[i].udata = udata;
        syscall_hooks[i].before = before;
        syscall_hooks[i].after = after;
        syscall_hooks[i].allow_skip = allow_skip;
        syscall_hooks[i].bypass_gate = bypass_gate;
        syscall_hook_barrier();
        syscall_hooks[i].state = CHAIN_ITEM_STATE_READY;
        if (i + 1 > syscall_hook_high) syscall_hook_high = i + 1;
        kp_private_spin_unlock(&syscall_hook_lock, flags);
        logkv("syscall hook add: nr %d compat %d, %llx, %llx\n", nr, is_compat, before, after);
        return HOOK_NO_ERR;
    }

    kp_private_spin_unlock(&syscall_hook_lock, flags);
    logkv("syscall hook add: nr %d compat %d failed\n", nr, is_compat);
    return -HOOK_CHAIN_FULL;
}

static void syscall_hook_remove(int nr, int is_compat, void *before, void *after)
{
    unsigned long flags = kp_private_spin_lock(&syscall_hook_lock);

    for (int i = 0; i < SYSCALL_HOOK_SLOT_NUM; i++) {
        if (syscall_hooks[i].state != CHAIN_ITEM_STATE_READY) continue;
        if (syscall_hooks[i].nr != nr || syscall_hooks[i].is_compat != is_compat) continue;
        int match = 0;
        if (before && syscall_hooks[i].before == before) match = 1;
        if (after && syscall_hooks[i].after == after) match = 1;
        if (!match) continue;
        syscall_hooks[i].state = CHAIN_ITEM_STATE_BUSY;
        syscall_hook_barrier();
        syscall_hooks[i].udata = 0;
        syscall_hooks[i].before = 0;
        syscall_hooks[i].after = 0;
        syscall_hooks[i].allow_skip = 0;
        syscall_hooks[i].bypass_gate = 0;
        syscall_hook_barrier();
        syscall_hooks[i].state = CHAIN_ITEM_STATE_EMPTY;
        break;
    }

    kp_private_spin_unlock(&syscall_hook_lock, flags);
}

int syscall_hook_global_enabled(void)
{
    return syscall_hook_global;
}

/* Register the single uid gate evaluated once per syscall before dispatching any
 * callback. Passing NULL disables gating (all callbacks run). */
void syscall_hook_set_gate(int (*gate)(void))
{
    syscall_hook_gate = gate;
}

void syscall_dispatch_init(void)
{
    if (syscall_hook_global) return;
    if (!kp_kpm_has_syscall_wrapper) {
        logki("syscall dispatcher: no syscall wrapper, keep per-syscall hooks\n");
        return;
    }

    /* Prefer invoke_syscall: it runs after syscall_trace_enter (seccomp/ptrace)
     * and before syscall_trace_exit, i.e. at the same granularity as the old
     * per-syscall hooks. Hooking there lets skip_origin skip only the real
     * handler while el0_svc_common still performs its entry/exit work. Fall back
     * to el0_svc_common, which is coarser and cannot honour skip_origin.
     * GCC clones (LTO/constprop/isra) get a trailing '.' suffix; the helper
     * requires that separator, so el0_svc_common_compat is not matched. */
    uintptr_t addr = 0;
    const char *name = 0;
    int granular = 0;

    addr = kallsyms_lookup_name_by_suffix("invoke_syscall");
    if (addr) {
        name = "invoke_syscall";
        granular = 1;
    }

    if (!addr) {
        addr = kallsyms_lookup_name_by_suffix("el0_svc_common");
        if (addr) {
            name = "el0_svc_common";
            uint32_t *insn = (uint32_t *)addr;
            if (insn[1] != 0xa9bd7bfd) {
                logki("Shadow Call Stack detected , bypass union syscall hook\n");
                return;
            }else{
                logki("Shadow Call Stack not detected, proceed with union syscall hook\n");
            }
        }
    }



    
    if (!addr) {
        logki("syscall dispatcher: no invoke_syscall/el0_svc_common, keep per-syscall hooks\n");
        return;
    }

    hook_err_t err = hook_wrap8((void *)addr, syscall_dispatch_before, syscall_dispatch_after, 0);
    if (err) {
        logki("syscall dispatcher: hook %s error %d, keep per-syscall hooks\n", name, err);
        return;
    }

    syscall_hook_handler_granular = granular;
    syscall_hook_barrier();
    syscall_hook_global = 1;
    logki("syscall dispatcher: hooked %s at %llx (skip_origin %s), global syscall hook enabled\n", name,
             (uint64_t)addr, granular ? "supported" : "unsupported");
}









struct kp_kpm_cred_offset {
    s16 usage_offset,
    subscribers_offset,
    magic_offset,
    uid_offset,
    gid_offset,
    suid_offset,
    sgid_offset,
    euid_offset,
    egid_offset,
    fsuid_offset,
    fsgid_offset,
    securebits_offset,
    cap_inheritable_offset,
    cap_permitted_offset,
    cap_effective_offset,
    cap_bset_offset,
    cap_ambient_offset,

    user_offset,
    user_ns_offset,
    ucounts_offset,
    group_info_offset,

    session_keyring_offset,
    process_keyring_offset,
    thread_keyring_offset,
    request_key_auth_offset,

    security_offset,

    rcu_offset;
};

static struct kp_kpm_cred_offset kp_kpm_cred_offset = {
    .usage_offset = offsetof(struct cred, usage),
    .subscribers_offset = -1,
    .magic_offset = -1,
    .uid_offset = offsetof(struct cred, uid),
    .gid_offset = offsetof(struct cred, gid),
    .suid_offset = offsetof(struct cred, suid),
    .sgid_offset = offsetof(struct cred, sgid),
    .euid_offset = offsetof(struct cred, euid),
    .egid_offset = offsetof(struct cred, egid),
    .fsuid_offset = offsetof(struct cred, fsuid),
    .fsgid_offset = offsetof(struct cred, fsgid),
    .securebits_offset = offsetof(struct cred, securebits),
    .cap_inheritable_offset = offsetof(struct cred, cap_inheritable),
    .cap_permitted_offset = offsetof(struct cred, cap_permitted),
    .cap_effective_offset = offsetof(struct cred, cap_effective),
    .cap_bset_offset = offsetof(struct cred, cap_bset),
    .cap_ambient_offset = offsetof(struct cred, cap_ambient),

    .user_offset = offsetof(struct cred, user),
    .user_ns_offset = offsetof(struct cred, user_ns),
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
    .ucounts_offset = offsetof(struct cred, ucounts),
    #else
    .ucounts_offset = -1,    
    #endif
    .group_info_offset = offsetof(struct cred, group_info),

    .session_keyring_offset = offsetof(struct cred, session_keyring),
    .process_keyring_offset = offsetof(struct cred, process_keyring),
    .thread_keyring_offset = offsetof(struct cred, thread_keyring),
    .request_key_auth_offset = offsetof(struct cred, request_key_auth),

    .security_offset = offsetof(struct cred, security),

    .rcu_offset = offsetof(struct cred, rcu),
};


struct kp_kpm_task_struct_offset {
	s16 pid_offset, tgid_offset, thread_pid_offset, ptracer_cred_offset;
	s16 real_cred_offset, cred_offset, comm_offset, fs_offset, files_offset;
	s16 loginuid_offset, sessionid_offset, seccomp_offset, security_offset;
	s16 stack_offset, tasks_offset, mm_offset, active_mm_offset;
};

static struct kp_kpm_task_struct_offset kp_kpm_task_struct_offset = {
	.pid_offset = offsetof(struct task_struct, pid),
	.tgid_offset = offsetof(struct task_struct, tgid),
	.thread_pid_offset = offsetof(struct task_struct, thread_pid),
	.ptracer_cred_offset = offsetof(struct task_struct, ptracer_cred),
	.real_cred_offset = offsetof(struct task_struct, real_cred),
	.cred_offset = offsetof(struct task_struct, cred),
	.comm_offset = offsetof(struct task_struct, comm),
	.fs_offset = offsetof(struct task_struct, fs),
	.files_offset = offsetof(struct task_struct, files),
	.loginuid_offset = -1,
	.sessionid_offset = -1,
	.seccomp_offset = offsetof(struct task_struct, seccomp),
	.security_offset = -1,
	.stack_offset = offsetof(struct task_struct, stack),
	.tasks_offset = offsetof(struct task_struct, tasks),
	.mm_offset = offsetof(struct task_struct, mm),
	.active_mm_offset = offsetof(struct task_struct, active_mm),
};

static u64 *kp_kpm_pgtable_entry(u64 pgd_addr, u64 va)
{
	pgd_t *pgd = (pgd_t *)pgd_addr + pgd_index(va);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	if (pgd_none(*pgd) || pgd_bad(*pgd))
		return NULL;
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		return NULL;
	pud = pud_offset(p4d, va);
	if (pud_none(*pud) || pud_bad(*pud))
		return NULL;
	if (pud_sect(*pud))
		return (u64 *)pud;
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		return NULL;
	if (pmd_sect(*pmd))
		return (u64 *)pmd;
	pte = pte_offset_kernel(pmd, va);
	return pte ? (u64 *)pte : NULL;
}

__attribute__((no_sanitize("cfi")))
static int kp_kpm_printk(const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;
	int rc;

	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	rc = printk("%pV", &vaf);
	va_end(args);
	return rc;
}

static int kp_kpm_copy_to_user(void __user *to, const void *from, int len)
{
	return copy_to_user(to, from, len) ? 0 : len;
}

static long kp_kpm_strncpy_from_user(char *dst, const char __user *src, long count)
{
	long rc = strncpy_from_user(dst, src, count);

	if (rc >= count) {
		dst[count - 1] = '\0';
		return count;
	}
	return rc > 0 ? rc + 1 : rc;
}

static uid_t kp_kpm_current_uid(void)
{
	return from_kuid(current_user_ns(), current_uid());
}

static long kp_kpm_hotpatch_nosync(void *addr, uint32_t value)
{
	uint32_t insn = value;
	return kp_patch_text(addr, &insn, sizeof(insn),
			     KP_PATCH_TEXT_FLUSH_DCACHE | KP_PATCH_TEXT_FLUSH_ICACHE);
}

struct kp_kpm_symbol {
	const char *name;
	unsigned long addr;
};

/* KPM headers declare printk/kallsyms_lookup_name/kallsyms_on_each_symbol as
 * function-pointer *variables* (extern void (*printk)(...)), so KPMs load the
 * pointer *stored at* the symbol address (adrp + ldr [x,#lo12] + blr).  The
 * symbols must therefore resolve to the address of a writable slot holding the
 * function pointer, not to the function's own code address (which would make
 * the ldr read the function prologue bytes as a pointer). */
static int (*kp_kpm_printk_fn)(const char *fmt, ...);
static unsigned long (*kp_kpm_kallsyms_lookup_name_fn)(const char *name);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
/* 6.4+ dropped the struct module * param from kallsyms_on_each_symbol's
 * callback; match the running kernel so the resolved pointer's kCFI type
 * hash lines up with kp_kpm_safe_kallsyms_on_each_symbol(). */
static int (*kp_kpm_kallsyms_on_each_symbol_fn)(
	int (*fn)(void *, const char *, unsigned long), void *data);
#else
static int (*kp_kpm_kallsyms_on_each_symbol_fn)(
	int (*fn)(void *, const char *, struct module *, unsigned long), void *data);
#endif

/* Same for the kf_* kfuncs (lib/string.c etc.): kfunc_def(name) is
 * (*kf_name), so a KPM referencing e.g. strncat accesses the pointer-variable
 * symbol kf_strncat and needs a slot, populated from the running kernel. */
#define KP_KPM_KFUNC_INIT(name) \
	kf_##name = (typeof(kf_##name))kallsyms_lookup_name(#name)
#define KP_KPM_KFUNC_ENTRY(name) \
	{ "kf_" #name, (unsigned long)&kf_##name }

static int (*kf_sprintf)(char *buf, const char *fmt, ...);
static int (*kf_snprintf)(char *buf, size_t size, const char *fmt, ...);
static int (*kf_vsnprintf)(char *buf, size_t size, const char *fmt, va_list args);
static char *(*kf_strcpy)(char *dest, const char *src);
static char *(*kf_strncpy)(char *dest, const char *src, size_t count);
static char *(*kf_strncat)(char *dest, const char *src, size_t count);
static int (*kf_strcmp)(const char *cs, const char *ct);
static int (*kf_strncmp)(const char *cs, const char *ct, size_t count);
static size_t (*kf_strlen)(const char *s);
static size_t (*kf_strnlen)(const char *s, size_t count);
static char *(*kf_strchr)(const char *s, int c);
static char *(*kf_strrchr)(const char *s, int c);
static char *(*kf_strstr)(const char *s1, const char *s2);
static void *(*kf_memset)(void *s, int c, size_t count);
static void *(*kf_memcpy)(void *dest, const void *src, size_t count);
static void *(*kf_memmove)(void *dest, const void *src, size_t count);
static int (*kf_memcmp)(const void *cs, const void *ct, size_t count);
static char *(*kf_kstrdup)(const char *s, gfp_t gfp);
static void *(*kf_kmemdup)(const void *src, size_t len, gfp_t gfp);
static char *(*kf_kasprintf)(gfp_t gfp, const char *fmt, ...);
static void *(*kf_memchr)(const void *s, int c, size_t n);
static char *(*kf_strcat)(char *dest, const char *src);

/* mm_struct offsets (mirrors kpimg's linux/mm_types.h) */
struct kp_kpm_mm_struct_offset {
	s16 mmap_base_offset;
	s16 task_size_offset;
	s16 pgd_offset;
	s16 map_count_offset;
	s16 total_vm_offset;
	s16 locked_vm_offset;
	s16 pinned_vm_offset;
	s16 data_vm_offset;
	s16 exec_vm_offset;
	s16 stack_vm_offset;
	s16 start_code_offset, end_code_offset, start_data_offset, end_data_offset;
	s16 start_brk_offset, brk_offset, start_stack_offset;
	s16 arg_start_offset, arg_end_offset, env_start_offset, env_end_offset;
};
static struct kp_kpm_mm_struct_offset kp_kpm_mm_struct_offset;

/* Syscall hooks: the LKM patches sys_call_table entries (fp path). */
static int kp_kpm_has_config_compat;

static uintptr_t kp_kpm_syscalln_name_addr(int nr, int is_compat)
{
	if (!is_compat && kp_sys_call_table)
		return kp_sys_call_table[nr];
	return 0;
}

static uintptr_t kp_kpm_syscalln_addr(int nr, int is_compat)
{
	if (!is_compat && kp_sys_call_table)
		return kp_sys_call_table[nr];
	return kp_kpm_syscalln_name_addr(nr, is_compat);
}

static int kp_kpm_hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
	/* Inline-hook the syscall function itself (kpimg's inline_wrap_syscalln).
	 * fp_hook_wrap lives in fphook.c which the LKM does not compile. */
	uintptr_t addr = kp_kpm_syscalln_addr(nr, 0);
	if (!addr)
		return -ENOENT;
	return hook_wrap((void *)addr, narg, before, after, udata);
}

static void kp_kpm_unhook_syscalln(int nr, void *before, void *after)
{
	uintptr_t addr = kp_kpm_syscalln_addr(nr, 0);
	if (addr)
		hook_unwrap((void *)addr, before, after);
}

static int kp_kpm_hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
	(void)nr; (void)narg; (void)before; (void)after; (void)udata;
	return -ENOSYS; /* no compat table on arm64 GKI */
}

static void kp_kpm_unhook_compat_syscalln(int nr, void *before, void *after)
{
	(void)nr; (void)before; (void)after;
}

static hook_err_t hook_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (syscall_hook_global)
        return syscall_hook_add(nr, 0, before, after, udata, 0, 0);
    // if (sys_call_table)
        // return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    // return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
    return -HOOK_CHAIN_FULL;
}

static void unhook_syscalln(int nr, void *before, void *after)
{
    if (syscall_hook_global)
        syscall_hook_remove(nr, 0, before, after);
    // if (sys_call_table)
        // return fp_unwrap_syscalln(nr, 0, before, after);
    // return inline_unwrap_syscalln(nr, 0, before, after);
}

static hook_err_t hook_compat_syscalln(int nr, int narg, void *before, void *after, void *udata)
{
    if (syscall_hook_global)
        return syscall_hook_add(nr, 1, before, after, udata, 0, 0);
    // if (compat_sys_call_table)
        // return fp_wrap_syscalln(nr, narg, 1, before, after, udata);
    // return inline_wrap_syscalln(nr, narg, 1, before, after, udata);
    return -HOOK_CHAIN_FULL;
}

static void unhook_compat_syscalln(int nr, void *before, void *after)
{
    if (syscall_hook_global)
        syscall_hook_remove(nr, 1, before, after);
    // if (compat_sys_call_table)
        // return fp_unwrap_syscalln(nr, 1, before, after);
    // return inline_unwrap_syscalln(nr, 1, before, after);
}

/* 支持 skip_origin 的版本（supercall 通道使用） */
static hook_err_t hook_syscalln_override(int nr, int narg, void *before, void *after, void *udata)
{
    if (syscall_hook_global && syscall_hook_handler_granular)
        return syscall_hook_add(nr, 0, before, after, udata, 1, 1);
    // if (sys_call_table)
        // return fp_wrap_syscalln(nr, narg, 0, before, after, udata);
    // return inline_wrap_syscalln(nr, narg, 0, before, after, udata);
    return -HOOK_CHAIN_FULL;
}

/* 强制 per-syscall 机制（回退 / legacy KPM 使用） */
static hook_err_t hook_syscalln_legacy(int nr, int narg, void *before, void *after, void *udata)
{
    return kp_kpm_hook_syscalln(nr, narg, before, after, udata);
}

/* task_pt_regs */
static struct pt_regs *kp_kpm_task_pt_reg(struct task_struct *task)
{
	unsigned long stack = (unsigned long)task_stack_page(task);
	return (struct pt_regs *)(THREAD_SIZE + stack - sizeof(struct pt_regs));
}

/* SU allowlist / exclude stubs — removed in slim build; KPMs that need these
 * should implement their own authorization logic. */
static int kp_kpm_is_su_allow_uid(uid_t uid)
{
	(void)uid;
	return 0;
}

static int kp_kpm_get_ap_mod_exclude(uid_t uid)
{
	(void)uid;
	return 0;
}

static int kp_kpm_set_ap_mod_exclude(uid_t uid, int exclude)
{
	(void)uid;
	(void)exclude;
	return 0;
}

static struct kp_kpm_symbol kp_kpm_symbols[] = {
	{ "compat_copy_to_user", (unsigned long)kp_kpm_copy_to_user },
	{ "compat_strncpy_from_user", (unsigned long)kp_kpm_strncpy_from_user },
	{ "current_uid", (unsigned long)kp_kpm_current_uid },
	{ "kver", (unsigned long)&kp_kpm_kver },
	{ "kpver", (unsigned long)&kp_kpm_kpver },
	{ "thread_size", (unsigned long)&kp_kpm_thread_size },
	{ "thread_info_in_task", (unsigned long)&kp_kpm_thread_info_in_task },
	{ "sp_el0_is_current", (unsigned long)&kp_kpm_sp_el0_is_current },
	{ "sp_el0_is_thread_info", (unsigned long)&kp_kpm_sp_el0_is_thread_info },
	{ "task_in_thread_info_offset", (unsigned long)&kp_kpm_task_in_thread_info_offset },
	{ "task_struct_offset", (unsigned long)&kp_kpm_task_struct_offset },
	{ "pgtable_entry", (unsigned long)kp_kpm_pgtable_entry },
	{ "printk", (unsigned long)&kp_kpm_printk_fn },
	{ "kallsyms_lookup_name", (unsigned long)&kp_kpm_kallsyms_lookup_name_fn },
	{ "kallsyms_on_each_symbol", (unsigned long)&kp_kpm_kallsyms_on_each_symbol_fn },
	KP_KPM_KFUNC_ENTRY(sprintf),
	KP_KPM_KFUNC_ENTRY(snprintf),
	KP_KPM_KFUNC_ENTRY(vsnprintf),
	KP_KPM_KFUNC_ENTRY(strcpy),
	KP_KPM_KFUNC_ENTRY(strncpy),
	KP_KPM_KFUNC_ENTRY(strncat),
	KP_KPM_KFUNC_ENTRY(strcmp),
	KP_KPM_KFUNC_ENTRY(strncmp),
	KP_KPM_KFUNC_ENTRY(strlen),
	KP_KPM_KFUNC_ENTRY(strnlen),
	KP_KPM_KFUNC_ENTRY(strchr),
	KP_KPM_KFUNC_ENTRY(strrchr),
	KP_KPM_KFUNC_ENTRY(strstr),
	KP_KPM_KFUNC_ENTRY(memset),
	KP_KPM_KFUNC_ENTRY(memcpy),
	KP_KPM_KFUNC_ENTRY(memmove),
	KP_KPM_KFUNC_ENTRY(memcmp),
	KP_KPM_KFUNC_ENTRY(kstrdup),
	KP_KPM_KFUNC_ENTRY(kmemdup),
	KP_KPM_KFUNC_ENTRY(kasprintf),
	KP_KPM_KFUNC_ENTRY(memchr),
	KP_KPM_KFUNC_ENTRY(strcat),
	{ "cred_offset", (unsigned long)&kp_kpm_cred_offset },
	{ "mm_struct_offset", (unsigned long)&kp_kpm_mm_struct_offset },
	{ "has_config_compat", (unsigned long)&kp_kpm_has_config_compat },
	{ "has_syscall_wrapper", (unsigned long)&kp_kpm_has_syscall_wrapper },
	{ "stack_in_task_offset", (unsigned long)&kp_kpm_stack_in_task_offset },
	{ "stack_end_offset", (unsigned long)&kp_kpm_stack_end_offset },
	{ "hook_syscalln", (unsigned long)hook_syscalln },
	{ "unhook_syscalln", (unsigned long)unhook_syscalln },
	{ "hook_compat_syscalln", (unsigned long)hook_compat_syscalln },
	{ "unhook_compat_syscalln", (unsigned long)unhook_compat_syscalln },
	{ "hook_syscalln_legacy", (unsigned long)hook_syscalln_legacy },
	{ "hook_syscalln_override", (unsigned long)hook_syscalln_override },
	{ "syscalln_addr", (unsigned long)kp_kpm_syscalln_addr },
	{ "syscalln_name_addr", (unsigned long)kp_kpm_syscalln_name_addr },
	{ "_task_pt_reg", (unsigned long)kp_kpm_task_pt_reg },
	{ "is_su_allow_uid", (unsigned long)kp_kpm_is_su_allow_uid },
	{ "get_ap_mod_exclude", (unsigned long)kp_kpm_get_ap_mod_exclude },
	{ "set_ap_mod_exclude", (unsigned long)kp_kpm_set_ap_mod_exclude },
	{ "hotpatch_nosync", (unsigned long)kp_kpm_hotpatch_nosync },
	{ "hook_wrap", (unsigned long)hook_wrap },
	{ "hook_unwrap_remove", (unsigned long)hook_unwrap_remove },
	{ "hook_chain_add", (unsigned long)hook_chain_add },
	{ "hook_chain_remove", (unsigned long)hook_chain_remove },
	{ "hook_prepare", (unsigned long)hook_prepare },
	{ "hook_install", (unsigned long)hook_install },
	{ "hook_uninstall", (unsigned long)hook_uninstall },
	{ "hook", (unsigned long)hook },
	{ "unhook", (unsigned long)unhook },
};

int kp_kpm_symbols_init(void)
{
	kp_kpm_printk_fn = kp_kpm_printk;
	kp_kpm_kallsyms_lookup_name_fn = kallsyms_lookup_name;
	/* Route KPM kallsyms iteration through the bti-c trampoline + CFI shield
	 * so Qualcomm's find_check_fn() panic and the BTI fault on bare-metal
	 * callbacks are avoided. */
	kp_kpm_kallsyms_on_each_symbol_fn = kp_kpm_safe_kallsyms_on_each_symbol;

	KP_KPM_KFUNC_INIT(sprintf);
	KP_KPM_KFUNC_INIT(snprintf);
	KP_KPM_KFUNC_INIT(vsnprintf);
	KP_KPM_KFUNC_INIT(strcpy);
	KP_KPM_KFUNC_INIT(strncpy);
	KP_KPM_KFUNC_INIT(strncat);
	KP_KPM_KFUNC_INIT(strcmp);
	KP_KPM_KFUNC_INIT(strncmp);
	KP_KPM_KFUNC_INIT(strlen);
	KP_KPM_KFUNC_INIT(strnlen);
	KP_KPM_KFUNC_INIT(strchr);
	KP_KPM_KFUNC_INIT(strrchr);
	KP_KPM_KFUNC_INIT(strstr);
	KP_KPM_KFUNC_INIT(memset);
	KP_KPM_KFUNC_INIT(memcpy);
	KP_KPM_KFUNC_INIT(memmove);
	KP_KPM_KFUNC_INIT(memcmp);
	KP_KPM_KFUNC_INIT(kstrdup);
	KP_KPM_KFUNC_INIT(kmemdup);
	KP_KPM_KFUNC_INIT(kasprintf);
	KP_KPM_KFUNC_INIT(memchr);
	KP_KPM_KFUNC_INIT(strcat);

	/* mm_struct offsets (5.15 arm64) */
	kp_kpm_mm_struct_offset.mmap_base_offset = offsetof(struct mm_struct, mmap_base);
	kp_kpm_mm_struct_offset.task_size_offset = offsetof(struct mm_struct, task_size);
	kp_kpm_mm_struct_offset.pgd_offset = offsetof(struct mm_struct, pgd);
	kp_kpm_mm_struct_offset.map_count_offset = offsetof(struct mm_struct, map_count);
	kp_kpm_mm_struct_offset.total_vm_offset = offsetof(struct mm_struct, total_vm);
	kp_kpm_mm_struct_offset.locked_vm_offset = offsetof(struct mm_struct, locked_vm);
	kp_kpm_mm_struct_offset.pinned_vm_offset = offsetof(struct mm_struct, pinned_vm);
	kp_kpm_mm_struct_offset.data_vm_offset = offsetof(struct mm_struct, data_vm);
	kp_kpm_mm_struct_offset.exec_vm_offset = offsetof(struct mm_struct, exec_vm);
	kp_kpm_mm_struct_offset.stack_vm_offset = offsetof(struct mm_struct, stack_vm);
	kp_kpm_mm_struct_offset.start_code_offset = offsetof(struct mm_struct, start_code);
	kp_kpm_mm_struct_offset.end_code_offset = offsetof(struct mm_struct, end_code);
	kp_kpm_mm_struct_offset.start_data_offset = offsetof(struct mm_struct, start_data);
	kp_kpm_mm_struct_offset.end_data_offset = offsetof(struct mm_struct, end_data);
	kp_kpm_mm_struct_offset.start_brk_offset = offsetof(struct mm_struct, start_brk);
	kp_kpm_mm_struct_offset.brk_offset = offsetof(struct mm_struct, brk);
	kp_kpm_mm_struct_offset.start_stack_offset = offsetof(struct mm_struct, start_stack);
	kp_kpm_mm_struct_offset.arg_start_offset = offsetof(struct mm_struct, arg_start);
	kp_kpm_mm_struct_offset.arg_end_offset = offsetof(struct mm_struct, arg_end);
	kp_kpm_mm_struct_offset.env_start_offset = offsetof(struct mm_struct, env_start);
	kp_kpm_mm_struct_offset.env_end_offset = offsetof(struct mm_struct, env_end);

	kp_kpm_has_config_compat = 0;

	/* arm64 GKI: syscalls go through __arm64_sys_* wrappers, so the KPM must
	 * parse syscall args with the wrapper ABI (narg + 1). */
	kp_kpm_has_syscall_wrapper = 0;
	if (kallsyms_lookup_name("__arm64_sys_openat"))
		kp_kpm_has_syscall_wrapper = 1;

	logki("kpm stack facts: stack_in_task=%d stack_end=%d has_syscall_wrapper=%d\n",
	      kp_kpm_stack_in_task_offset, kp_kpm_stack_end_offset,
	      kp_kpm_has_syscall_wrapper);

	logki("kpm compatibility symbol table ready (%zu symbols) printk=%px "
	      "kallsyms_lookup_name=%px kf_strncat=%px kf_strcmp=%px\n",
	      ARRAY_SIZE(kp_kpm_symbols), kp_kpm_printk_fn, kp_kpm_kallsyms_lookup_name_fn,
	      kf_strncat, kf_strcmp);
	return 0;
}

unsigned long kp_kpm_symbol_lookup(const char *name)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(kp_kpm_symbols); i++) {
		if (!strcmp(name, kp_kpm_symbols[i].name))
			return kp_kpm_symbols[i].addr;
	}
	return 0;
}
