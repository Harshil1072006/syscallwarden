# Measured results

The source for every result in this table is the bundled Linux workload's witness stream. The run used x86-64 Linux 6.18.57, Python 3.12.14 and GCC 14.2.0 for native C tests. Raw machine-readable results are in [benchmark.json](evidence/benchmark.json).

| Case | Label | Observed rule | Outcome |
|---|---|---|---|
| related-shell | Connection-to-shell pattern | SW-001 | TP |
| preload-marker | Nonempty preload on exec | SW-002 | TP |
| attach-attempt | Unapproved attach attempt | SW-003 | TP |
| shell-alone | Benign | None | TN |
| connect-only | Benign | None | TN |
| empty-preload | Benign | None | TN |
| siblings | Benign, connection and shell in different branches | None | TN |
| failed-connect | Benign, closed local port then shell | None | TN |
| health-check | Benign, health response then shell checks procfs | SW-001 | FP |

| Measure | Calculation or sample | Result |
|---|---|---:|
| Sensitivity | 3 / (3 + 0) | 100% |
| False-positive rate | 1 / (1 + 5) | 16.67% |
| Precision | 3 / (3 + 1) | 75% |
| p50 processing latency | Per decoded event, 4,400 timings | 1.692 µs |
| p95 processing latency | Same timings, nearest rank | 2.423 µs |

## Method

1. Launch each of the nine named scenarios from `lab/workload.py` separately. The positive shell surrogate connects to a server bound by the same process, closes both ends and starts a child shell with a fixed command. The benign health scenario exchanges a fixed health response and runs a shell to inspect its own status. These operations satisfy the same correlation rule.
2. Parse the actor's self-observed JSON lines. Each case gets a fresh engine. Ground truth comes from `tests/cases.json`; the actor emits no expected rules or truth labels. A positive case succeeds when its named rule appears. Any alert on a benign case is a false positive. The separate tests check the exact matched rules.
3. Reuse the 22 decoded events for 200 rounds with fresh process state per case. Time individual calls to `Engine.accept` using `perf_counter_ns`. The interval includes validation, dictionary lookups, lineage traversal and in-memory snapshot construction. JSON parsing, kernel transport, process startup, disk I/O and HTML rendering are outside that interval. Timer overhead is included. Results vary with load and Python version.
4. Run the complete workload again independently to produce the review evidence. Four alerts over 22 witness events appear in [the HTML report](evidence/incidents.html). The saved [JSON report](evidence/incidents.json) and [raw JSONL](evidence/events.jsonl) let a reviewer check every relationship.

```sh
make test
make bench
```

Nine authored cases give narrow coverage. The positive labels describe observable signals. No remote command session, loaded injection module or successful attachment was used to produce these scores. Repeating the same records provides timing samples only. It adds no independent detection examples.

## Verification status

| Component | Evidence in this release |
|---|---|
| Workload, rule engine, JSON and HTML | Executed locally against the shipped actor; 13 tests passed in 0.793 s |
| C sample encoder | Native-compiled and tested with escaped names, IPv6, ptrace, wrong sizes and invalid kinds |
| C hook logic | Native-compiled with stand-ins for kernel helpers; exercised scope checks, correlation of entry and exit, preload scanning and loss counting |
| Go daemon tests, image builds and unprivileged Compose demo | Implemented in CI; execution requires a Go and Docker toolchain |
| Kernel verifier, attachment, transport overhead and live detection rate | Awaiting the documented `make live` acceptance run |

The test run, analyzer summary and loader diagnostic from the missing preload marker are stored in [tests.txt](evidence/tests.txt), [run.txt](evidence/run.txt) and [workload-stderr.txt](evidence/workload-stderr.txt).
