#ifndef WARDEN_WIRE_H
#define WARDEN_WIRE_H
#include <linux/types.h>
enum event_kind { W_FORK = 1, W_EXEC, W_CONNECT, W_PTRACE, W_EXIT };
enum counters { RING_LOSS, MAP_LOSS, ENV_INCOMPLETE, COUNTER_COUNT };
struct scope { __u64 cgroup, ns_dev, ns_ino; };
struct peer { __u16 family, port; __u8 ip[16]; };
struct pending_exec { char path[96]; __u8 preload; };
struct sample {
    __u64 t, birth, pbirth;
    __u32 pid, ppid, kind;
    __s32 ret, request, target;
    struct peer peer;
    __u8 preload;
    char name[96];
};
#endif
