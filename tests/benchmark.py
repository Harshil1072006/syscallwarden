"""Score independently labelled lab runs and measure only Engine.accept for latency."""
import json
import math
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src/warden"))
from analyze import Engine


def percentile(data, fraction):
    return sorted(data)[math.ceil(len(data) * fraction) - 1]


def measure():
    labels = json.loads((ROOT / "tests/cases.json").read_text())
    corpora, results = [], []
    for case, expected in labels.items():
        p = subprocess.run([sys.executable, ROOT / "lab/workload.py", case],
                           capture_output=True, check=True)
        events = [json.loads(line) for line in p.stdout.splitlines()]
        corpora.append(events)
        engine = Engine()
        for e in events:
            engine.accept(e)
        rules = sorted(r for r, n in engine.counts.items() if n)
        outcome = ("TP" if expected in rules else "FN") if expected else ("FP" if rules else "TN")
        results.append(dict(case=case, expected=expected, observed=rules, outcome=outcome))
    durations = []
    config = Engine().cfg
    for _ in range(200):
        for events in corpora:
            engine = Engine(config)
            for e in events:
                before = time.perf_counter_ns()
                engine.accept(e)
                durations.append(time.perf_counter_ns() - before)
    return {"source": "lab-witness", "python": platform.python_version(),
            "system": platform.system(), "machine": platform.machine(),
            "cases": results, "samples": len(durations), "rounds": 200,
            "processing_us_p50": round(statistics.median(durations) / 1000, 3),
            "processing_us_p95": round(percentile(durations, .95) / 1000, 3),
            "counts": {k: sum(r["outcome"] == k for r in results) for k in ("TP","FP","TN","FN")}}


if __name__ == "__main__":
    print(json.dumps(measure(), indent=2))
