// SPDX-License-Identifier: MIT
#define _GNU_SOURCE
#include "encode.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "../bpf/wire.h"

static volatile sig_atomic_t stopping;
static void stop(int sig) { (void)sig; stopping = 1; }

int main(int argc, char **argv)
{
    int result = 1, nfds = 0;
    struct bpf_link *links[32] = {};
    struct ring_buffer *rb = NULL;
    struct bpf_object *obj = NULL;
    struct stat ns, cg;
    char comm[32] = {}, *end = NULL;
    struct scope scope = {};
    // PID 1 must be the bundled actor, in a different private cgroup.
    FILE *f = fopen("/proc/1/comm", "r");
    if (f) { if (!fgets(comm, sizeof(comm), f)) comm[0] = 0; fclose(f); }
    if (argc != 2 || strcmp(comm, "sw-lab\n") ||
        stat("/proc/self/ns/pid", &ns) || stat("/sys/fs/cgroup", &cg) ||
        access("/sys/fs/cgroup/cgroup.controllers", R_OK)) {
        fprintf(stderr, "Bundled lab PID namespace and cgroup v2 required\n"); return 1;
    }
    errno = 0;
    scope.cgroup = strtoull(argv[1], &end, 10);
    if (errno || *end || argv[1][0] < '1' || argv[1][0] > '9' ||
        !scope.cgroup || scope.cgroup == cg.st_ino) {
        fprintf(stderr, "Invalid lab cgroup\n"); return 1;
    }
    scope.ns_dev = ns.st_dev;
    scope.ns_ino = ns.st_ino;
    obj = bpf_object__open_file("/opt/warden/warden.bpf.o", NULL);
    if (!obj || libbpf_get_error(obj)) { obj = NULL; goto fail; }
    if (bpf_object__load(obj)) goto fail;
    __u32 zero = 0;
    int settings_fd = bpf_object__find_map_fd_by_name(obj, "settings");
    int events_fd = bpf_object__find_map_fd_by_name(obj, "events");
    int stats_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    if (settings_fd < 0 || events_fd < 0 || stats_fd < 0 ||
        bpf_map_update_elem(settings_fd, &zero, &scope, BPF_ANY)) goto fail;
    rb = ring_buffer__new(events_fd, encode_sample, NULL, NULL);
    if (!rb || libbpf_get_error(rb)) { rb = NULL; goto fail; }

    struct bpf_program *p;
    bpf_object__for_each_program(p, obj) {
        if (nfds == 32) goto fail;
        struct bpf_link *link = bpf_program__attach(p);
        if (!link || libbpf_get_error(link)) goto fail;
        links[nfds++] = link;
    }
    signal(SIGTERM, stop);
    signal(SIGINT, stop);
    setvbuf(stdout, NULL, _IOLBF, 0);
    // Dedicated readiness fd supplied by the Go supervisor.
    if (write(3, "READY\n", 6) != 6) goto fail;
    close(3);
    while (!stopping) {
        int rc = ring_buffer__poll(rb, 80);
        if (rc < 0 && rc != -EINTR) goto fail;
    }
    while (nfds) bpf_link__destroy(links[--nfds]);
    if (ring_buffer__consume(rb) < 0) goto fail;
    __u64 values[COUNTER_COUNT] = {};
    for (__u32 i = 0; i < COUNTER_COUNT; i++) {
        if (bpf_map_lookup_elem(stats_fd, &i, &values[i])) goto fail;
    }
    fprintf(stderr, "ring_loss=%llu map_loss=%llu incomplete_env_scans=%llu\n",
            values[RING_LOSS], values[MAP_LOSS], values[ENV_INCOMPLETE]);
    result = !!(values[RING_LOSS] || values[MAP_LOSS] || values[ENV_INCOMPLETE] || fflush(stdout));
    goto out;
fail:
    fprintf(stderr, "Capture failed: %s\n", strerror(errno));
out:
    while (nfds) bpf_link__destroy(links[--nfds]);
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return result;
}
