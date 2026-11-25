"""Independent acceptance assertions for the complete bundled lab."""
import json
import sys

EXPECTED = {"SW-001": 2, "SW-002": 1, "SW-003": 1}


def check(report, source):
    if report["source"] != source or report["counts"] != EXPECTED:
        raise ValueError(f"unexpected source or counts: {report['source']} {report['counts']}")
    if report["omitted_snapshots"] or report["evicted_processes"] or len(report["incidents"]) != 4:
        raise ValueError("incomplete lab report")
    for i in report["incidents"]:
        ev = i["evidence"]
        if i["rule"] == "SW-001":
            if (len(ev) != 2 or ev[0]["kind"] != "connect" or ev[0]["ret"] != 0
                    or ev[0]["ip"] != "127.0.0.1" or ev[1]["name"] != "/bin/sh"
                    or (ev[1]["ppid"], ev[1]["pbirth"]) != (ev[0]["pid"], ev[0]["birth"])):
                raise ValueError("shell matched the wrong connection")
        if i["rule"] == "SW-002" and (ev[0]["name"] != "/bin/true" or not ev[0]["preload"]):
            raise ValueError("missing preload evidence")
        if i["rule"] == "SW-003" and (ev[0]["request"], ev[0]["target"]) != (16, 0):
            raise ValueError("unexpected ptrace request")


if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        check(json.load(f), sys.argv[2])
    print("PASS lab assertions: 2 related shells, 1 preload marker, 1 attach attempt")
