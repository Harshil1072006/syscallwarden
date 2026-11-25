// Native unit-test stand-ins for Linux helper calls, never included in the BPF ELF.
#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#define SEC(x)
#define __uint(n, v) int (*n)[v]
#define __type(n, t) t *n
#define FIELD1(p,a) ((p)->a)
#define FIELD2(p,a,b) ((p)->a->b)
#define PICK(_1,_2,NAME,...) NAME
#define BPF_CORE_READ(p,...) PICK(__VA_ARGS__,FIELD2,FIELD1)(p,__VA_ARGS__)
#define bpf_ntohs(x) ntohs(x)
static int bpf_probe_read_user(void *dst, size_t size, const void *src)
{
    if (!src) return -1;
    memcpy(dst, src, size);
    return 0;
}
static int bpf_probe_read_user_str(void *dst, size_t size, const void *src)
{
    if (!src || !size) return -1;
    size_t n = strnlen(src, size-1);
    memcpy(dst, src, n);
    ((char *)dst)[n] = 0;
    return (int)n + 1;
}
#define bpf_core_read_str bpf_probe_read_user_str
static void *bpf_map_lookup_elem(void *, const void *);
static int bpf_map_update_elem(void *, const void *, const void *, int);
static int bpf_map_delete_elem(void *, const void *);
static void *bpf_ringbuf_reserve(void *, size_t, int);
static void bpf_ringbuf_submit(void *, int);
static uint64_t bpf_get_current_cgroup_id(void);
static int bpf_get_ns_current_pid_tgid(uint64_t, uint64_t, struct bpf_pidns_info *, size_t);
static uint64_t bpf_get_current_pid_tgid(void);
static uint64_t bpf_ktime_get_ns(void);
static void *bpf_get_current_task(void);
