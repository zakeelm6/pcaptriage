"""Detect regular beaconing from an internal host to an external server (possible C2).

Two tests, because real implants do not all behave alike:

* strict: the intervals between connections have a tiny coefficient of
  variation. Catches a metronome-like beacon.
* robust: the *median* interval is stable (MAD/median small) even though some
  gaps are long. A beacon that sleeps now and then has a huge standard
  deviation but a very stable median, which is what the CV test misses.

Only external destinations are considered: internal polling (monitoring,
domain controllers) is normal and would drown the signal.
"""

from __future__ import annotations

from collections import defaultdict
from statistics import mean, median, pstdev
from typing import Dict, List

from .base import Finding, fmt_ts, register
from .suspicious_download import is_external

# Minimum connections to the same destination to judge regularity.
MIN_CONNECTIONS = 15
# Strict test: coefficient of variation below this = metronome.
CV_HIGH = 0.10
# Robust test: MAD / median below these.
MAD_HIGH = 0.05
MAD_MEDIUM = 0.20
# Below this median interval the traffic is a burst (parallel downloads,
# page loads), not a beacon.
MIN_MEDIAN_SECONDS = 1.0


@register
def detect_beaconing(logs: Dict[str, List[dict]]) -> List[Finding]:
    conns = logs.get("conn", [])
    if not conns:
        return []

    times: Dict[tuple, List[float]] = defaultdict(list)
    for rec in conns:
        src, dst, port, ts = (rec.get("id.orig_h"), rec.get("id.resp_h"),
                              rec.get("id.resp_p"), rec.get("ts"))
        if src and dst and isinstance(ts, (int, float)) and is_external(dst):
            times[(src, dst, port)].append(ts)

    findings: List[Finding] = []
    for (src, dst, port), ts_list in times.items():
        if len(ts_list) < MIN_CONNECTIONS:
            continue
        ts_list.sort()
        deltas = [b - a for a, b in zip(ts_list, ts_list[1:]) if b - a > 0]
        if len(deltas) < MIN_CONNECTIONS - 1:
            continue
        med = median(deltas)
        if med < MIN_MEDIAN_SECONDS:
            continue
        m = mean(deltas)
        cv = pstdev(deltas) / m
        mad_ratio = median(abs(d - med) for d in deltas) / med

        if cv <= CV_HIGH or mad_ratio <= MAD_HIGH:
            severity = "high"
        elif mad_ratio <= MAD_MEDIUM:
            severity = "medium"
        else:
            continue

        gaps = sum(1 for d in deltas if d > 5 * med)
        findings.append(
            Finding(
                id="beaconing",
                title=f"Regular beaconing {src} -> {dst}:{port}",
                severity=severity,
                description=(
                    "A host contacted the same external server at a steady rhythm. "
                    "Automated, periodic callbacks are a common sign of "
                    "command-and-control (C2) traffic, including implants that "
                    "sleep between check-ins."
                ),
                mitre=["T1071", "T1095"],
                evidence=[
                    f"source: {src}",
                    f"destination: {dst}:{port}",
                    f"connections: {len(ts_list)}",
                    f"first seen: {fmt_ts(ts_list[0])}",
                    f"last seen: {fmt_ts(ts_list[-1])}",
                    f"median interval: {med:.1f} s",
                    f"stability of the median (MAD/median): {mad_ratio:.3f} (lower = more regular)",
                    f"coefficient of variation: {cv:.3f}",
                    f"long pauses (> 5x median): {gaps}",
                ],
                source_log="conn",
                hosts=[src],
                servers=[dst],
            )
        )

    return findings
