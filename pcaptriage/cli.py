"""Command-line interface for pcaptriage."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

from . import __version__
from .correlation import build_narrative
from .detections import all_detections
from .loader import load_logs
from .report import build_summary, render_html
from .zeek_runner import ZeekError, run_zeek

PCAP_EXTS = {".pcap", ".pcapng", ".cap"}


def _analyze_one(pcap: Path, out_root: Path, args) -> int:
    """Analyze a single pcap. Returns the number of findings."""
    case_dir = out_root / pcap.stem
    logs_dir = case_dir / "zeek-logs"
    print(f"[*] {pcap.name}: running Zeek ({'docker' if args.docker else 'local'})...")
    try:
        run_zeek(
            str(pcap),
            str(logs_dir),
            use_docker=args.docker,
            zeek_cmd=args.zeek_cmd,
            docker_image=args.docker_image,
        )
    except ZeekError as exc:
        print(f"[!] {pcap.name}: {exc}", file=sys.stderr)
        return -1

    logs = load_logs(str(logs_dir))
    findings = []
    for detect in all_detections():
        findings.extend(detect(logs))

    summary = build_summary(logs)
    narrative = build_narrative(findings)

    report_path = case_dir / "report.html"
    report_path.write_text(render_html(pcap.name, summary, findings, narrative), encoding="utf-8")

    json_path = case_dir / "findings.json"
    json_path.write_text(
        json.dumps(
            {
                "pcap": pcap.name,
                "summary": {k: v for k, v in summary.items()},
                "narrative": narrative,
                "findings": [f.to_dict() for f in findings],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    sev = {}
    for f in findings:
        sev[f.severity] = sev.get(f.severity, 0) + 1
    sev_str = ", ".join(f"{v} {k}" for k, v in sorted(sev.items())) or "none"
    print(f"[+] {pcap.name}: {len(findings)} finding(s) ({sev_str}) -> {report_path}")
    return len(findings)


def _collect_pcaps(target: Path) -> List[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(p for p in target.rglob("*") if p.suffix.lower() in PCAP_EXTS)
    return []


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="pcaptriage",
        description="Automated pcap triage on top of Zeek, mapped to MITRE ATT&CK.",
    )
    parser.add_argument("target", help="a .pcap file or a directory of captures")
    parser.add_argument(
        "-o", "--output", default="pcaptriage-report",
        help="output directory (default: ./pcaptriage-report)",
    )
    parser.add_argument(
        "--docker", action="store_true",
        help="run Zeek via Docker instead of a local install",
    )
    parser.add_argument(
        "--zeek-cmd", default="zeek",
        help="local Zeek binary name/path (default: zeek)",
    )
    parser.add_argument(
        "--docker-image", default="zeek/zeek:lts",
        help="Zeek Docker image (default: zeek/zeek:lts)",
    )
    parser.add_argument("--version", action="version", version=f"pcaptriage {__version__}")
    args = parser.parse_args(argv)

    target = Path(args.target)
    pcaps = _collect_pcaps(target)
    if not pcaps:
        print(f"[!] no pcap found at: {target}", file=sys.stderr)
        return 2

    out_root = Path(args.output)
    out_root.mkdir(parents=True, exist_ok=True)

    total = 0
    failures = 0
    for pcap in pcaps:
        n = _analyze_one(pcap, out_root, args)
        if n < 0:
            failures += 1
        else:
            total += n

    print(f"\n[=] done: {len(pcaps) - failures}/{len(pcaps)} capture(s) analyzed, "
          f"{total} finding(s) total. Reports in {out_root}/")
    return 1 if failures and failures == len(pcaps) else 0


if __name__ == "__main__":
    raise SystemExit(main())
