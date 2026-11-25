import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src/warden"), str(ROOT / "lab")]
import analyze
import verify
import workload


def ev(kind="exec", **kw):
    obj = dict(kind=kind, t=20_000_000_000, pid=3, birth=30, ppid=2, pbirth=20, name="/bin/sh")
    if kind == "exec":
        obj.update(preload=False)
    elif kind == "connect":
        obj.update(pid=2, birth=20, ppid=1, pbirth=10, name="worker", ip="::1", port=15, ret=0)
    return dict(obj, **kw)


class Rules(unittest.TestCase):
    def test_inclusive_window_and_future(self):
        base = ev("connect")
        for dt, hits in [(0,1), (1_500_000_000,1), (1_500_000_001,0), (-1,0)]:
            with self.subTest(dt=dt):
                e = analyze.Engine()
                e.accept(base)
                e.accept(ev(t=base["t"] + dt))
                self.assertEqual(e.counts["SW-001"], hits)

    def test_pid_reuse_and_unrelated_actor(self):
        for shell in (ev(pbirth=21), ev(ppid=4, pbirth=20)):
            e = analyze.Engine()
            e.accept(ev("connect"))
            e.accept(shell)
            self.assertEqual(e.counts["SW-001"], 0)

    def test_failed_connect_and_nonshell(self):
        for rc, name in [(-111, "sh"), (0, "fish-food")]:
            e = analyze.Engine()
            e.accept(ev("connect", ret=rc))
            e.accept(ev(name=name))
            self.assertFalse(any(e.counts.values()))

    def test_three_edges_and_depth_bound(self):
        for depth, expected in ((3,1), (4,0)):
            e = analyze.Engine()
            e.accept(ev("connect", pid=1, birth=1, ppid=0, pbirth=0))
            for i in range(2, depth+1):
                e.accept(ev("fork", pid=i, birth=i, ppid=i-1, pbirth=i-1, name="worker"))
            e.accept(ev(pid=depth+1, birth=depth+1, ppid=depth, pbirth=depth))
            self.assertEqual(e.counts["SW-001"], expected)

    def test_cyclic_or_missing_parents(self):
        e = analyze.Engine()
        e.accept(ev(ppid=3, pbirth=30, preload=True))
        self.assertEqual(len(e.incidents[0]["lineage"]), 1)

    def test_ptrace_approval_request_type_and_preload(self):
        e = analyze.Engine()
        e.cfg["approved_tracers"] = ["gdb"]
        for req, name in [(16,"gdb"), (1,"unlisted"), (0x4206,"unlisted")]:
            e.accept(ev("ptrace", request=req, target=0, name=name))
        e.accept(ev(preload=False))
        e.accept(ev(preload=True))
        self.assertEqual(e.counts, {"SW-001":0, "SW-002":1, "SW-003":1})

    def test_limits_and_snapshot_immutability(self):
        e = analyze.Engine()
        with patch.object(analyze, "LIMIT", 2), patch.object(analyze, "MAX_INCIDENTS", 1):
            e.accept(ev(preload=True))
            saved = copy.deepcopy(e.incidents)
            for i in range(4,7):
                e.accept(ev(pid=i, birth=i, preload=True))
            self.assertEqual(saved, e.incidents)
            self.assertEqual((e.omitted, e.evictions, len(e.nodes)), (3,2,2))

    def test_input_and_html_safety(self):
        for record in (ev("unknown"), ev(preload=1), ev(birth=0), ev("connect", ip="bad")):
            with self.assertRaises(ValueError):
                analyze.validate(record)
        e = analyze.Engine()
        e.accept(ev(name="<script>", preload=True))
        page = analyze.page(e.report("fixture"))
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>", page)

    def test_cli_rejects_invalid_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            for data in (b'{"kind":"bad"}\n', b"x"*8200):
                p = subprocess.run([sys.executable, analyze.__file__, "--source", "fixture", "--out", tmp],
                                   input=data, capture_output=True)
                self.assertNotEqual(p.returncode, 0)
                self.assertEqual(list(Path(tmp).iterdir()), [])


class BundledLab(unittest.TestCase):
    def test_each_labelled_workload(self):
        labels = json.loads((ROOT / "tests/cases.json").read_text())
        self.assertEqual(set(labels), set(workload.CASES))
        for case, expected in labels.items():
            with self.subTest(case=case):
                p = subprocess.run([sys.executable, workload.__file__, case], capture_output=True, check=True)
                e = analyze.Engine()
                for line in p.stdout.splitlines():
                    e.accept(json.loads(line))
                actual = [i["rule"] for i in e.incidents]
                self.assertEqual(actual, ["SW-001"] if case == "health-check" else [expected] if expected else [])

    def test_complete_workload_reports(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run([sys.executable, workload.__file__, "all"], check=True, capture_output=True)
            result = subprocess.run([sys.executable, analyze.__file__, "--source", "lab-witness", "--out", tmp],
                                    input=p.stdout, check=True, capture_output=True)
            report = json.loads((Path(tmp) / "incidents.json").read_text())
            verify.check(report, "lab-witness")
            self.assertIn("SW-003=1", result.stdout.decode())
            self.assertIn("lab-witness", (Path(tmp) / "incidents.html").read_text())

    def test_probe_hook_logic_with_helper_standins(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "probe-test"
            subprocess.run([os.environ.get("CC", "cc"), "-std=gnu11", "-O2", "-Wall", "-Werror",
                            "-Wno-attributes", "-Wno-unknown-pragmas", ROOT / "tests/probe_test.c",
                            "-o", binary], check=True)
            self.assertIn(b"PASS native probe semantics", subprocess.check_output([binary]))

    def test_c_encoder_to_engine(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "encode-test"
            subprocess.run([os.environ.get("CC","cc"), "-std=c11", "-Wall", "-Wextra", "-Werror",
                            ROOT / "tests/encode_test.c", ROOT / "src/collector/encode.c", "-o", binary], check=True)
            rows = [analyze.validate(json.loads(s)) for s in subprocess.check_output([binary]).splitlines()]
            self.assertEqual(rows[0]["name"], 'image"\\\n')
            self.assertEqual((rows[1]["ip"], rows[1]["port"], rows[1]["ret"]), ("::1",1234,-111))
            e = analyze.Engine()
            for row in rows:
                e.accept(row)
            self.assertEqual(e.counts, {"SW-001":0,"SW-002":1,"SW-003":1})


if __name__ == "__main__":
    unittest.main()
