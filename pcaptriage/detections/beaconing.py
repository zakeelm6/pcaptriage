"""Detect regular beaconing to a destination (possible C2)."""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, pstdev
from typing import Dict, List

from .base import Finding, register

# Minimum connections to the same destination to judge regularity.
MIN_CONNECTIONS = 10
# Coefficient of variation of inter-arrival times below this = very regular.
CV_HIGH = 0.10
CV_MEDIUM = 0.25


@register
def detect_beaconing(logs: Dict[str, List[dict]]) -> List[Finding]:
    conns = logs.get("conn", [])
    if not conns:
        return []

    # Group connection start times per (src, dst, dst_port).
    times: Dict[tuple, List[float]] = defaultdict(list)
    for rec in conns:
        src = rec.get("id.orig_h")
        dst = rec.get("id.resp_h")
        port = rec.get("id.resp_p")
        ts = rec.get("ts")
        if src and dst and isinstance(ts, (int, float)):
            times[(src, dst, port)].append(ts)

    findings: List[Finding] = []
    for (src, dst, port), ts_list in times.items():
        if len(ts_list) < MIN_CONNECTIONS:
            continue
        ts_list.sort()
        deltas = [b - a for a, b in zip(ts_list, ts_list[1:]) if b - a > 0]
        if len(deltas) < MIN_CONNECTIONS - 1:
            continue
        m = mean(deltas)
        if m <= 0:
            continue
        cv = pstdev(deltas) / m
        if cv > CV_MEDIUM:
            continue
        severity = "high" if cv <= CV_HIGH else "medium"
        findings.append(
            Finding(
                id="beaconing",
                title=f"Regular beaconing {src} -> {dst}:{port}",
                severity=severity,
                description=(
                    "A host contacted the same destination at a near-constant "
                    "interval. Regular, automated callbacks are a common sign of "
                    "command-and-control (C2) traffic."
                ),
                mitre=["T1071", "T1095"],
                evidence=[
                    f"source: {src}",
                    f"destination: {dst}:{port}",
                    f"connections: {len(ts_list)}",
                    f"mean interval: {m:.1f} s",
                    f"interval regularity (CV): {cv:.3f} (lower = more regular)",
                ],
                source_log="conn",
                hosts=[src, dst],
            )
        )

    return findings
