// Execute the actual hook functions against deterministic kernel-helper stand-ins.
#define _GNU_SOURCE
#define WARDEN_NATIVE_PROBE_TEST
#include "../src/bpf/warden.bpf.c"
#include <assert.h>
#include <stdio.h>

static struct task_struct lab_task, parent_task;
static struct scope lab_scope = {7, 2, 3};
static struct pending_exec cached_exec;
static struct peer cached_peer;
static struct sample output;
static __u64 totals[COUNTER_COUNT];
static int have_exec, have_peer, submitted, ring_full, ns_ok = 1;
static uint64_t current_cg = 7;
static void *bpf_get_current_task(void) { return &lab_task; }
static uint64_t bpf_get_current_cgroup_id(void) { return current_cg; }
static uint64_t bpf_get_current_pid_tgid(void) { return (42ULL << 32) | 42; }
static uint64_t bpf_ktime_get_ns(void) { return 1000; }
static int bpf_get_ns_current_pid_tgid(uint64_t dev, uint64_t ino, struct bpf_pidns_info *p, size_t n)
{
    (void)p;
    return !(ns_ok && dev == 2 && ino == 3 && n == sizeof(*p));
}
static void *bpf_map_lookup_elem(void *map, const void *key)
{
    if (map == &settings) return &lab_scope;
    if (map == &stats) return &totals[*(const __u32 *)key];
    assert(*(const __u64 *)key == bpf_get_current_pid_tgid());
    if (map == &execs) return have_exec ? &cached_exec : NULL;
    assert(map == &connects);
    return have_peer ? &cached_peer : NULL;
}
static int bpf_map_update_elem(void *map, const void *key, const void *value, int flags)
{
    (void)flags;
    assert(*(const __u64 *)key == bpf_get_current_pid_tgid());
    if (map == &execs) { memcpy(&cached_exec, value, sizeof(cached_exec)); have_exec = 1; }
    else { assert(map == &connects); memcpy(&cached_peer, value, sizeof(cached_peer)); have_peer = 1; }
    return 0;
}
static int bpf_map_delete_elem(void *map, const void *key)
{
    assert(*(const __u64 *)key == bpf_get_current_pid_tgid());
    if (map == &execs) have_exec = 0;
    else { assert(map == &connects); have_peer = 0; }
    return 0;
}
static void *bpf_ringbuf_reserve(void *map, size_t sz, int flags)
{
    (void)flags;
    assert(map == &events && sz == sizeof(output));
    return ring_full ? NULL : &output;
}
static void bpf_ringbuf_submit(void *s, int flags)
{
    (void)flags;
    assert(s == &output);
    ++submitted;
}

int main(void)
{
    parent_task = (struct task_struct){.pid=1,.tgid=1,.start_boottime=10,.group_leader=&parent_task};
    lab_task = (struct task_struct){.pid=42,.tgid=42,.start_boottime=12,.group_leader=&lab_task,
                                    .real_parent=&parent_task,.comm="sw-lab"};
    struct enter c = {.args={16, 0}};
    current_cg = 100;
    enter_ptrace(&c);
    current_cg = 7; ns_ok = 0;
    enter_ptrace(&c);
    assert(submitted == 0);
    ns_ok = 1;
    enter_ptrace(&c);
    assert(submitted == 1 && output.kind == W_PTRACE && output.pbirth == 10 && output.pid == 42);
    c.args[0] = 1;
    enter_ptrace(&c);
    assert(submitted == 1);

    struct sockaddr_in sa = {.sin_family=AF_INET,.sin_port=htons(321)};
    assert(inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr) == 1);
    c = (struct enter){.args={5,(unsigned long)&sa,sizeof(sa)}};
    enter_connect(&c);
    struct leave ret = {.ret=-111};
    exit_connect(&ret);
    assert(submitted == 2 && output.ret == -111 && output.peer.port == 321 && !have_peer);
    c.args[2] = 2;
    enter_connect(&c);
    exit_connect(&ret);
    assert(submitted == 2);

    const char *env[] = {"LD_PRELOAD=", "LD_PRELOADX=foo", "LD_PRELOAD=marker", NULL};
    c = (struct enter){.args={(unsigned long)"/bin/true",0,(unsigned long)env}};
    enter_exec(&c);
    assert(have_exec && cached_exec.preload);
    __u64 raw[2] = {0,42};
    successful_exec((void *)raw);
    assert(submitted == 3 && output.preload && !strcmp(output.name,"/bin/true") && !have_exec);
    env[2] = NULL;
    enter_exec(&c);
    assert(have_exec && !cached_exec.preload);
    exit_exec(&ret);
    assert(!have_exec && submitted == 3);

    const char *many[34];
    for (int i=0; i<32; i++) many[i]="X=Y";
    many[32]="LD_PRELOAD=outside-window"; many[33]=NULL;
    save_exec("/bin/true",many);
    assert(!cached_exec.preload && totals[ENV_INCOMPLETE] == 1);
    ring_full = 1;
    exit_task(NULL);
    assert(totals[RING_LOSS] == 1 && !have_exec && submitted == 3);
    puts("PASS native probe semantics");
    return 0;
}
