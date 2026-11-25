// SPDX-License-Identifier: MIT
#include "encode.h"
#include "../bpf/wire.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>

static void quoted(const char *s, size_t n)
{
    putchar('"');
    for (size_t i = 0; i < n && s[i]; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') { putchar('\\'); putchar(c); }
        else if (c < 32 || c > 126) printf("\\u%04x", c);
        else putchar(c);
    }
    putchar('"');
}

int encode_sample(void *unused, void *data, size_t sz)
{
    (void)unused;
    static const char *const kinds[] = {"", "fork", "exec", "connect", "ptrace", "exit"};
    const struct sample *e = data;
    if (sz != sizeof(*e) || e->kind < W_FORK || e->kind > W_EXIT) return -EINVAL;
    printf("{\"kind\":\"%s\",\"t\":%llu,\"pid\":%u,\"birth\":%llu,"
           "\"ppid\":%u,\"pbirth\":%llu,\"name\":", kinds[e->kind],
           e->t, e->pid, e->birth, e->ppid, e->pbirth);
    quoted(e->name, sizeof(e->name));
    if (e->kind == W_CONNECT) {
        char ip[INET6_ADDRSTRLEN];
        if (!inet_ntop(e->peer.family, e->peer.ip, ip, sizeof(ip))) return -EINVAL;
        printf(",\"ip\":\"%s\",\"port\":%u,\"ret\":%d", ip, e->peer.port, e->ret);
    } else if (e->kind == W_EXEC) {
        printf(",\"preload\":%s", e->preload ? "true" : "false");
    } else if (e->kind == W_PTRACE) {
        printf(",\"request\":%d,\"target\":%d", e->request, e->target);
    }
    puts("}");
    return ferror(stdout) ? -EIO : 0;
}

