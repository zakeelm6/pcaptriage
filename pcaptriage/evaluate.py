"""Score the detections against a list of expected behaviours.

    python -m pcaptriage.evaluate --expected validation/x.expected.json --logs DIR
    python -m pcaptriage.evaluate --expected validation/x.expected.json --pcap x.pcap --docker

The expectation file says which finding ids a capture must produce (and how
many), and which ids it must NOT produce. It names no address and no domain, so
it can be published without the capture. Exit status is 1 when something that
was expected is missing or something forbidden shows up, so it can gate a CI job.

The expectations are only as good as whoever wrote them: they are a record of
what a person established by reading the logs, not an official answer key.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

from .loader import load_logs
from .pipeline import Options, detect_all
from .zeek_runner import ZeekError, run_zeek


def score(found: Counter, expected: dict) -> dict:
    expect = expected.get("expect", {})
    forbid = set(expected.get("forbid", []))
    return {
        "found": {k: found[k] for k in expect if found[k] >= expect[k]},
        "missed": {k: {"expected": n, "found": found[k]} for k, n in expect.items() if found[k] < n},
        "false_positives": {k: found[k] for k in forbid if found[k]},
        "unlisted": {k: n for k, n in found.items() if k not in expect and k not in forbid},
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="pcaptriage.evaluate", description=__doc__.split("\n\n")[0])
    p.add_argument("--expected", required=True, help="expectation JSON file")
    src = p.add_mutually_exclusive_group(required=True)
    src.add_argument("--logs", help="directory of Zeek JSON logs already produced")
    src.add_argument("--pcap", help="capture to run Zeek on first")
    p.add_argument("--docker", action="store_true", help="run Zeek via Docker (with --pcap)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    a = p.parse_args(argv)

    expected = json.loads(Path(a.expected).read_text(encoding="utf-8"))
    tmp = None
    logs_dir = a.logs
    if a.pcap:
        tmp = tempfile.TemporaryDirectory(prefix="pcaptriage-eval-")
        logs_dir = tmp.name
        try:
            run_zeek(a.pcap, logs_dir, use_docker=a.docker)
        except ZeekError as exc:
            print(f"[!] {exc}", file=sys.stderr)
            return 2

    findings = detect_all(load_logs(logs_dir), Options(decode=True))
    result = score(Counter(f.id for f in findings), expected)
    if tmp:
        tmp.cleanup()

    bad = bool(result["missed"] or result["false_positives"])
    if a.json:
        print(json.dumps({"name": expected.get("name", ""), **result, "ok": not bad}, indent=2))
    else:
        def fmt(d, kind):
            if kind == "missed":
                return ", ".join(
                    "%s (expected >= %d, found %d)" % (k, v["expected"], v["found"])
                    for k, v in d.items()
                ) or "-"
            return ", ".join("%s x%d" % (k, n) for k, n in d.items()) or "-"

        print("capture: %s" % expected.get("name", "(unnamed)"))
        print("  found:             %s" % fmt(result["found"], "count"))
        print("  MISSED:            %s" % fmt(result["missed"], "missed"))
        print("  FALSE POSITIVES:   %s" % fmt(result["false_positives"], "count"))
        print("  unlisted (review): %s" % fmt(result["unlisted"], "count"))
        print("  result:", "FAIL" if bad else "OK")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
