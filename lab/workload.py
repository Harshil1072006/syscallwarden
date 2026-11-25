"""Finite, closed-loop lab. It has no command, address or PID arguments."""
import argparse
import ctypes
import errno
import json
import os
import select
import socket
import struct
import sys
import time
from pathlib import Path

CASES = ("related-shell", "preload-marker", "attach-attempt", "shell-alone",
         "connect-only", "empty-preload", "siblings", "failed-connect", "health-check")
LIBC = ctypes.CDLL(None, use_errno=True)
CONTROL = "/run/warden/lab.sock"


def identity():
    # Fields after the closing parenthesis start at field 3. Field 22 is starttime.
    stat = Path("/proc/self/stat").read_text().rsplit(")", 1)[1].split()
    return os.getpid(), int(stat[19])


def event(kind, who, parent, name, **fields):
    return dict(kind=kind, t=time.monotonic_ns(), pid=who[0], birth=who[1],
                ppid=parent[0], pbirth=parent[1], name=name, **fields)


def write(fd, obj):
    data = (json.dumps(obj, separators=(",", ":")) + "\n").encode()
    if os.write(fd, data) != len(data):
        raise RuntimeError("short lab write")


def wait(pid):
    _, status = os.waitpid(pid, 0)
    if os.waitstatus_to_exitcode(status):
        raise RuntimeError(f"lab child {pid} failed: {status}")


def child(fn):
    pid = os.fork()
    if pid == 0:
        try:
            fn()
        except BaseException as exc:
            os.write(2, (repr(exc) + "\n").encode())
            os._exit(111)
        os._exit(0)
    wait(pid)


def run_exec(fd, shell=False, preload=None, health=False):
    parent = identity()
    rd, wr = os.pipe()
    path = "/bin/sh" if shell else "/bin/true"
    # Fixed command, no input, socket, user arguments or inherited environment.
    command = "test -r /proc/self/status" if health else "exit 0"
    argv = [path, "-c", command] if shell else [path]
    env = {} if preload is None else {"LD_PRELOAD": preload}
    pid = os.fork()
    if pid == 0:
        try:
            os.close(rd)
            obj = event("exec", identity(), parent, path, preload=bool(preload))
            write(wr, obj)
            os.close(wr)
            os.close(fd)
            os.execve(path, argv, env)
        except BaseException:
            os._exit(112)
    os.close(wr)
    with os.fdopen(rd, "rb") as pipe:
        record = pipe.readline()
    wait(pid)  # Emit only after the fixed executable has successfully completed.
    data = json.loads(record)
    write(fd, data)


def connect(fd, parent, succeed=True, health=False):
    with socket.socket() as server, socket.socket() as client:
        server.bind(("127.0.0.1", 0))
        if succeed:
            server.listen(1)
        ip, port = server.getsockname()
        rc = client.connect_ex((ip, port))
        if (rc == 0) != succeed or (not succeed and rc != errno.ECONNREFUSED):
            raise RuntimeError(f"unexpected connect result {rc}")
        if succeed:
            peer, _ = server.accept()
            with peer:
                if health:
                    peer.sendall(b"OK\n")
                    with client.makefile("rb") as stream:
                        if stream.readline(4) != b"OK\n":
                            raise RuntimeError("health check failed")
    write(fd, event("connect", identity(), parent, "sw-lab", ip=ip, port=port, ret=-rc))


def scenario(name, fd, parent):
    who = identity()
    write(fd, event("fork", who, parent, "sw-lab"))
    if name in ("related-shell", "health-check", "connect-only", "failed-connect"):
        connect(fd, parent, name != "failed-connect", health=name == "health-check")
    elif name == "siblings":
        child(lambda: connect(fd, who))
    if name in ("related-shell", "shell-alone", "health-check", "siblings", "failed-connect"):
        run_exec(fd, shell=True, health=name == "health-check")
    elif name in ("preload-marker", "empty-preload"):
        # This intentionally absent pathname produces a loader warning and loads no code.
        run_exec(fd, preload="/__syscallwarden_absent__/marker.so" if name == "preload-marker" else "")
    elif name == "attach-attempt":
        # PID 0 is an invalid tracee. No process can be attached by this fixture.
        ret = LIBC.ptrace(16, 0, None, None)
        if ret != -1:
            raise RuntimeError("invalid tracee unexpectedly accepted")
        write(fd, event("ptrace", who, parent, "sw-lab", request=16, target=0))


def run_cases(fd, names):
    parent = identity()
    for name in names:
        child(lambda: scenario(name, fd, parent))


def serve():
    if os.getpid() != 1:
        raise RuntimeError("serve requires PID 1 in the bundled lab container")
    if LIBC.prctl(15, b"sw-lab", 0, 0, 0) != 0:
        raise RuntimeError("failed to mark lab process")
    Path(CONTROL).unlink(missing_ok=True)
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(CONTROL)
        os.chmod(CONTROL, 0o666)
        listener.listen(1)
        listener.settimeout(120)
        client, _ = listener.accept()
        with client, client.makefile("rb") as inp:
            client.settimeout(100)
            peer = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            peer_pid, _, _ = struct.unpack("3i", peer)
            if peer_pid <= 1:
                raise RuntimeError("sensor must share the bundled lab PID namespace")
            # Exiting PID 1 terminates all processes in this namespace. Hold its
            # lifetime until the exact sensor process has published and exited.
            peer_fd = os.pidfd_open(peer_pid)
            root = Path("/sys/fs/cgroup")
            if not (root / "cgroup.controllers").is_file():
                raise RuntimeError("cgroup v2 required")
            cg = root.stat().st_ino
            client.sendall(f"SCOPE {cg}\n".encode())
            if inp.readline(32) != b"START\n":
                raise RuntimeError("invalid start")
            run_cases(client.fileno(), CASES)
            client.sendall(b"DONE\n")
            if inp.readline(32) != b"ACK\n":
                raise RuntimeError("missing acknowledgement")
            poller = select.poll()
            poller.register(peer_fd, select.POLLIN)
            try:
                if not poller.poll(15000):
                    raise RuntimeError("sensor did not exit after acknowledging the lab")
            finally:
                os.close(peer_fd)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("case", choices=(*CASES, "all", "serve"))
    case = parser.parse_args().case
    if case == "serve":
        serve()
    else:
        if LIBC.prctl(15, b"sw-lab", 0, 0, 0) != 0:
            sys.exit("failed to mark lab process")
        run_cases(1, CASES if case == "all" else [case])
