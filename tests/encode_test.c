// Constructs ABI samples solely to exercise the live collector's real JSON encoder.
#include "../src/collector/encode.h"
#include "../src/bpf/wire.h"
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
int main(void)
{
    struct sample e = {.t=100,.pid=42,.birth=43,.ppid=1,.pbirth=2,.kind=W_EXEC,.preload=1};
    strcpy(e.name, "image\"\\\n");
    assert(encode_sample(NULL, &e, sizeof(e)-1) == -EINVAL);
    assert(!encode_sample(NULL, &e, sizeof(e)));
    e.kind = W_CONNECT;
    e.peer.family = AF_INET6;
    e.peer.port = 1234;
    e.ret = -111;
    assert(inet_pton(AF_INET6, "::1", e.peer.ip) == 1);
    assert(!encode_sample(NULL, &e, sizeof(e)));
    e.kind = W_PTRACE;
    e.request = 16;
    assert(!encode_sample(NULL, &e, sizeof(e)));
    e.kind = 99;
    assert(encode_sample(NULL, &e, sizeof(e)) == -EINVAL);
    return 0;
}
