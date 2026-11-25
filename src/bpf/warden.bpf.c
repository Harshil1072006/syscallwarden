// SPDX-License-Identifier: GPL-2.0 OR MIT
#include <linux/bpf.h>
#ifdef WARDEN_NATIVE_PROBE_TEST
#include "../../tests/probe_shim.h"
#else
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#endif
#include "wire.h"

// Minimal CO-RE projection; kernel BTF resolves the real field offsets.
struct task_struct {
    int pid, tgid;
    unsigned long long start_boottime;
    struct task_struct *group_leader, *real_parent;
    char comm[16];
} __attribute__((preserve_access_index));

// Native 64-bit Linux syscalls tracepoint layout (x86_64 / arm64).
struct enter { __u64 header; long nr; unsigned long args[6]; };
struct leave { __u64 header; long nr, ret; };

#define MAP(name, kind, keytype, valtype, maximum) \
struct { __uint(type, kind); __uint(max_entries, maximum); \
         __type(key, keytype); __type(value, valtype); } name SEC(".maps")
MAP(settings, BPF_MAP_TYPE_ARRAY, __u32, struct scope, 1);
MAP(stats, BPF_MAP_TYPE_ARRAY, __u32, __u64, COUNTER_COUNT);
MAP(execs, BPF_MAP_TYPE_HASH, __u64, struct pending_exec, 1024);
MAP(connects, BPF_MAP_TYPE_HASH, __u64, struct peer, 1024);
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } events SEC(".maps");

static __always_inline void count(__u32 key)
{
    __u64 *v = bpf_map_lookup_elem(&stats, &key);
    if (v) __sync_fetch_and_add(v, 1);
}
static __always_inline int in_scope(void)
{
    __u32 key = 0;
    struct scope *s = bpf_map_lookup_elem(&settings, &key);
    struct bpf_pidns_info info = {};
    return s && s->cgroup && bpf_get_current_cgroup_id() == s->cgroup &&
        !bpf_get_ns_current_pid_tgid(s->ns_dev, s->ns_ino, &info, sizeof(info));
}
static __always_inline struct sample *begin(__u32 kind, struct task_struct *task)
{
    struct sample *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { count(RING_LOSS); return 0; }
    __builtin_memset(e, 0, sizeof(*e));
    struct task_struct *leader = BPF_CORE_READ(task, group_leader);
    struct task_struct *parent = BPF_CORE_READ(leader, real_parent, group_leader);
    e->kind = kind;
    e->t = bpf_ktime_get_ns();
    e->pid = BPF_CORE_READ(leader, tgid);
    e->birth = BPF_CORE_READ(leader, start_boottime);
    e->ppid = BPF_CORE_READ(parent, tgid);
    e->pbirth = BPF_CORE_READ(parent, start_boottime);
    bpf_core_read_str(e->name, sizeof(task->comm), &task->comm);
    return e;
}

SEC("raw_tracepoint/sched_process_fork")
int fork_event(struct bpf_raw_tracepoint_args *ctx)
{
    if (!in_scope()) return 0;
    struct task_struct *child = (void *)ctx->args[1];
    if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid)) return 0;
    struct sample *e = begin(W_FORK, child);
    if (e) bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int save_exec(const char *path, const char **env)
{
    if (!in_scope()) return 0;
    struct pending_exec x = {};
    bpf_probe_read_user_str(x.path, sizeof(x.path), path);
    // Never copy a complete environment entry into userspace.
    for (int i = 0; i < 32; i++) {
        const char *p = 0;
        char prefix[13] = {};
        if (bpf_probe_read_user(&p, sizeof(p), env + i)) { count(ENV_INCOMPLETE); break; }
        if (!p) break;
        if (bpf_probe_read_user_str(prefix, sizeof(prefix), p) < 0) {
            count(ENV_INCOMPLETE);
            continue;
        }
        int match = 1;
        // A fixed comparison avoids generating a libc memcmp call in BPF.
#pragma clang loop unroll(full)
        for (int j = 0; j < 11; ++j) {
            if (prefix[j] != "LD_PRELOAD="[j]) match = 0;
        }
        if (match && prefix[11]) {
            x.preload = 1;
            break;
        }
        if (i == 31) count(ENV_INCOMPLETE);
    }
    __u64 tid = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&execs, &tid, &x, BPF_ANY)) count(MAP_LOSS);
    return 0;
}
SEC("tracepoint/syscalls/sys_enter_execve")
int enter_exec(struct enter *c) { return save_exec((void *)c->args[0], (void *)c->args[2]); }
SEC("tracepoint/syscalls/sys_enter_execveat")
int enter_execat(struct enter *c) { return save_exec((void *)c->args[1], (void *)c->args[3]); }

SEC("raw_tracepoint/sched_process_exec")
int successful_exec(struct bpf_raw_tracepoint_args *ctx)
{
    if (!in_scope()) return 0;
    // sched_process_exec provides old_pid for exec from a non-leader thread.
    __u64 tid = (bpf_get_current_pid_tgid() & 0xffffffff00000000ULL) | (__u32)ctx->args[1];
    struct pending_exec *x = bpf_map_lookup_elem(&execs, &tid);
    struct sample *e = begin(W_EXEC, (void *)bpf_get_current_task());
    if (e) {
        if (x) {
            if (x->path[0]) __builtin_memcpy(e->name, x->path, sizeof(e->name));
            e->preload = x->preload;
        } else count(MAP_LOSS);
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&execs, &tid);
    return 0;
}
static __always_inline int cleanup_exec(struct leave *c)
{
    if (c->ret < 0 && in_scope()) {
        __u64 tid = bpf_get_current_pid_tgid();
        bpf_map_delete_elem(&execs, &tid);
    }
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_execve")
int exit_exec(struct leave *c) { return cleanup_exec(c); }
SEC("tracepoint/syscalls/sys_exit_execveat")
int exit_execat(struct leave *c) { return cleanup_exec(c); }

SEC("tracepoint/syscalls/sys_enter_connect")
int enter_connect(struct enter *c)
{
    if (!in_scope()) return 0;
    const char *sa = (void *)c->args[1];
    int length = (int)c->args[2];
    struct peer p = {};
    if (length < 4 || bpf_probe_read_user(&p.family, 2, sa)) return 0;
    if (p.family == 2 && length >= 16) {
        if (bpf_probe_read_user(p.ip, 4, sa + 4)) return 0;
    } else if (p.family == 10 && length >= 28) {
        if (bpf_probe_read_user(p.ip, 16, sa + 8)) return 0;
    } else return 0;
    if (bpf_probe_read_user(&p.port, 2, sa + 2)) return 0;
    p.port = bpf_ntohs(p.port);
    __u64 tid = bpf_get_current_pid_tgid();
    if (bpf_map_update_elem(&connects, &tid, &p, BPF_ANY)) count(MAP_LOSS);
    return 0;
}
SEC("tracepoint/syscalls/sys_exit_connect")
int exit_connect(struct leave *c)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    struct peer *p = bpf_map_lookup_elem(&connects, &tid);
    if (!p) return 0;
    struct sample *e = begin(W_CONNECT, (void *)bpf_get_current_task());
    if (e) {
        e->peer = *p;
        e->ret = c->ret;
        bpf_ringbuf_submit(e, 0);
    }
    bpf_map_delete_elem(&connects, &tid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_ptrace")
int enter_ptrace(struct enter *c)
{
    if (!in_scope()) return 0;
    if (c->args[0] != 16 && c->args[0] != 0x4206) return 0;
    struct sample *e = begin(W_PTRACE, (void *)bpf_get_current_task());
    if (e) {
        e->request = c->args[0];
        e->target = c->args[1];
        bpf_ringbuf_submit(e, 0);
    }
    return 0;
}

SEC("raw_tracepoint/sched_process_exit")
int exit_task(void *ctx)
{
    if (!in_scope()) return 0;
    __u64 tid = bpf_get_current_pid_tgid();
    bpf_map_delete_elem(&execs, &tid);
    bpf_map_delete_elem(&connects, &tid);
    if ((__u32)tid != (tid >> 32)) return 0;
    struct sample *e = begin(W_EXIT, (void *)bpf_get_current_task());
    if (e) bpf_ringbuf_submit(e, 0);
    return 0;
}
char LICENSE[] SEC("license") = "Dual MIT/GPL";
