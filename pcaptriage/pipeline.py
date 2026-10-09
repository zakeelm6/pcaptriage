"""The analysis pipeline shared by the CLI and the web UI."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import List

from .artifacts import collect_artifacts
from .correlation import build_narrative
from .decode import decode_findings
from .detections import all_detections
from .detections.base import Finding
from .indicators import build_indicators
from .loader import load_logs
from .report import build_summary, render_html
from .zeek_runner import run_zeek

PCAP_EXTS = {".pcap", ".pcapng", ".cap"}


@dataclass
class Options:
    use_docker: bool = False
    zeek_cmd: str = "zeek"
    docker_image: str = "zeek/zeek:lts"
    decode: bool = False
    decode_schemes: str = ""
    decode_strict: bool = False
    artifacts: bool = False


@dataclass
class Result:
    pcap_name: str
    case_dir: Path
    report_path: Path
    json_path: Path
    findings: List[Finding]
    narrative: list
    artifacts: list = None  # type: ignore[assignment]
    indicators: list = None  # type: ignore[assignment]
    summary: dict = None  # type: ignore[assignment]

    def severity_counts(self) -> dict:
        counts: dict = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts


def detect_all(logs: dict, opts: Options) -> List[Finding]:
    """Every detection, plus decoding when asked, over already-loaded Zeek logs."""
    findings: List[Finding] = []
    for detect in all_detections():
        findings.extend(detect(logs))
    if opts.decode:
        schemes = [s.strip() for s in opts.decode_schemes.split(",") if s.strip()]
        findings.extend(decode_findings(logs, schemes, strict=opts.decode_strict))
    return findings


def analyze_pcap(pcap: Path, out_root: Path, opts: Options) -> Result:
    """Run Zeek, the detections and the report for one capture.

    Raises ZeekError if Zeek cannot be run or produces nothing.
    """
    case_dir = out_root / pcap.stem
    logs_dir = case_dir / "zeek-logs"
    run_zeek(
        str(pcap),
        str(logs_dir),
        use_docker=opts.use_docker,
        zeek_cmd=opts.zeek_cmd,
        docker_image=opts.docker_image,
        extract=opts.artifacts,
    )

    logs = load_logs(str(logs_dir))
    findings = detect_all(logs, opts)

    summary = build_summary(logs)
    narrative = build_narrative(findings)
    artifacts = collect_artifacts(logs, case_dir) if opts.artifacts else []
    indicators = build_indicators(logs, findings)

    report_path = case_dir / "report.html"
    report_path.write_text(
        render_html(pcap.name, summary, findings, narrative, artifacts, indicators), encoding="utf-8"
    )

    json_path = case_dir / "findings.json"
    json_path.write_text(
        json.dumps(
            {
                "pcap": pcap.name,
                "summary": {k: v for k, v in summary.items()},
                "narrative": narrative,
                "indicators": indicators,
                "artifacts": artifacts,
                "findings": [f.to_dict() for f in findings],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    return Result(pcap.name, case_dir, report_path, json_path, findings, narrative, artifacts, indicators, summary)
