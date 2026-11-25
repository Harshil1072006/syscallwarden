"""Streaming, bounded Linux event correlation and incident reporting. Python 3.11+."""
import argparse
import html
import ipaddress
import json
import os
import sys
import tempfile
from collections import OrderedDict
from pathlib import Path

LIMIT = 8192
MAX_INCIDENTS = 1024
KINDS = {"fork", "exec", "connect", "ptrace", "exit"}
RULES = Path(__file__).resolve().parents[2] / "rules/default.json"


def uint(value, name, minimum=0):
    if type(value) is not int or not minimum <= value < 2**64:
        raise ValueError(f"invalid {name}")
    return value


def validate(e):
    if not isinstance(e, dict) or e.get("kind") not in KINDS:
        raise ValueError("unknown event kind")
    for k in ("t", "pid", "birth", "ppid", "pbirth"):
        uint(e.get(k), k, 1 if k in ("t", "pid", "birth") else 0)
    name = e.get("name")
    if not isinstance(name, str) or not 0 < len(name) <= 256:
        raise ValueError("invalid image name")
    k = e["kind"]
    if k == "exec" and type(e.get("preload")) is not bool:
        raise ValueError("invalid preload flag")
    if k == "connect":
        ipaddress.ip_address(e["ip"])
        if uint(e.get("port"), "port") > 65535 or type(e.get("ret")) is not int:
            raise ValueError("invalid connect result")
    if k == "ptrace" and any(type(e.get(f)) is not int for f in ("request", "target")):
        raise ValueError("invalid ptrace fields")
    return e


class Engine:
    def __init__(self, config=None):
        self.cfg = config or json.loads(RULES.read_text())
        self.nodes = OrderedDict()
        self.incidents = []
        self.events = self.evictions = self.omitted = 0
        self.counts = {r: 0 for r in self.cfg["titles"]}

    def lineage(self, key):
        seen, chain = set(), []
        for _ in range(self.cfg["ancestor_edges"] + 1):
            if key in seen or key not in self.nodes:
                break
            seen.add(key)
            node = self.nodes[key]
            chain.append((key, node))
            key = node["parent"]
        return chain

    def record(self, rule, event, chain, evidence):
        self.counts[rule] += 1
        if len(self.incidents) >= MAX_INCIDENTS:
            self.omitted += 1
            return
        tree = [{"pid": k[0], "birth": k[1], "name": n["name"]} for k, n in chain]
        self.incidents.append({"rule": rule, "title": self.cfg["titles"][rule],
                               "t": event["t"], "lineage": tree,
                               "evidence": evidence})

    def accept(self, event):
        e = validate(event)
        self.events += 1
        key, kind = (e["pid"], e["birth"]), e["kind"]
        # Birth time distinguishes a reused PID. Retain exited ancestors for
        # historical snapshots until normal bounded eviction.
        node = self.nodes.setdefault(key, {"connection": None, "name": e["name"]})
        self.nodes.move_to_end(key)
        if len(self.nodes) > LIMIT:
            self.nodes.popitem(last=False)
            self.evictions += 1
        node.update(parent=(e["ppid"], e["pbirth"]), name=e["name"])
        if kind == "connect" and e["ret"] == 0:
            node["connection"] = e
        elif kind == "ptrace":
            if e["request"] in (16, 0x4206) and e["name"] not in self.cfg["approved_tracers"]:
                self.record("SW-003", e, self.lineage(key), [e])
        elif kind == "exec":
            chain = self.lineage(key)
            if e["preload"]:
                self.record("SW-002", e, chain, [e])
            if os.path.basename(e["name"]) in self.cfg["shells"]:
                for _, relative in chain:
                    c = relative["connection"]
                    if c and 0 <= e["t"] - c["t"] <= self.cfg["window_ms"] * 1_000_000:
                        self.record("SW-001", e, chain, [c, e])
                        break

    def report(self, source):
        return {"schema": 1, "source": source, "events": self.events,
                "counts": self.counts, "evicted_processes": self.evictions,
                "omitted_snapshots": self.omitted, "incidents": self.incidents}


def page(r):
    esc = lambda x: html.escape(str(x), quote=True)
    cards = []
    for i in r["incidents"]:
        tree = " ← ".join(f'{n["name"]} [{n["pid"]}]' for n in i["lineage"])
        evidence = json.dumps(i["evidence"], indent=2, ensure_ascii=True)
        cards.append(f'<article><small>{esc(i["rule"])}</small><h2>{esc(i["title"])}</h2>'
                     f'<p>{esc(tree)}</p><details><summary>Event evidence</summary>'
                     f'<pre>{esc(evidence)}</pre></details></article>')
    summary = " · ".join(f"{k} × {v}" for k, v in r["counts"].items())
    return f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>SyscallWarden incident report</title><style>
body{{max-width:58rem;margin:3rem auto;padding:0 1.2rem;background:#f8f7f2;color:#162c35;font:1rem/1.55 system-ui}}
article{{border-top:1px solid #9ba9a9;padding:1.2rem 0}}h1{{font-size:2.5rem}}h2{{font-size:1.2rem}}
small,summary{{color:#145e61}}pre{{overflow:auto;padding:1rem;background:#e8efed}}
</style><main><h1>SyscallWarden</h1><p>{esc(r['source'])} · {r['events']} events</p>
<p>{esc(summary)}</p><p>Process evictions {r['evicted_processes']} · Omitted snapshots {r['omitted_snapshots']}</p>
{''.join(cards) or '<p>No rules matched.</p>'}</main></html>"""


def write_report(directory, report):
    directory.mkdir(parents=True, exist_ok=True)
    for filename, data in (("incidents.json", json.dumps(report, indent=2) + "\n"),
                           ("incidents.html", page(report))):
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as f:
            try:
                f.write(data)
                f.flush()
                os.replace(f.name, directory / filename)
            finally:
                Path(f.name).unlink(missing_ok=True)


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--source", required=True, choices=["lab-witness", "kernel-ringbuf", "fixture"])
    p.add_argument("--out", required=True, type=Path)
    args = p.parse_args()
    engine = Engine()
    while line := sys.stdin.buffer.readline(8193):
        if len(line) > 8192:
            raise ValueError("oversized event")
        engine.accept(json.loads(line))
    write_report(args.out, engine.report(args.source))
    print(f"source={args.source} events={engine.events} " +
          " ".join(f"{k}={v}" for k, v in engine.counts.items()))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError) as err:
        sys.exit(f"analysis failed: {err}")
