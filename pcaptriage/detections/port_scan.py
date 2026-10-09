"""Detect port/host scanning from conn.log."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from .base import Finding, register

# A source touching this many distinct destination ports looks like a scan.
PORT_THRESHOLD = 50
# A source touching this many distinct hosts looks like a sweep.
HOST_THRESHOLD = 25
# Connection states typical of scans (no payload / rejected / reset).
SCAN_STATES = {"S0", "REJ", "RSTR", "RSTOS0", "SH", "OTH"}


@register
def detect_port_scan(logs: Dict[str, List[dict]]) -> List[Finding]:
    conns = logs.get("conn", [])
    if not conns:
        return []

    ports_by_src: Dict[str, Set[int]] = defaultdict(set)
    hosts_by_src: Dict[str, Set[str]] = defaultdict(set)
    scanlike_by_src: Dict[str, int] = defaultdict(int)

    for rec in conns:
        src = rec.get("id.orig_h")
        dst = rec.get("id.resp_h")
        port = rec.get("id.resp_p")
        state = rec.get("conn_state", "")
        if src is None:
            continue
        if port is not None:
            ports_by_src[src].add(port)
        if dst is not None:
            hosts_by_src[src].add(dst)
        if state in SCAN_STATES:
            scanlike_by_src[src] += 1

    findings: List[Finding] = []
    for src in sorted(ports_by_src, key=lambda s: len(ports_by_src[s]), reverse=True):
        n_ports = len(ports_by_src[src])
        n_hosts = len(hosts_by_src[src])
        n_scanlike = scanlike_by_src.get(src, 0)

        if n_ports >= PORT_THRESHOLD or n_hosts >= HOST_THRESHOLD:
            evidence = [
                f"source {src}",
                f"distinct destination ports: {n_ports}",
                f"distinct destination hosts: {n_hosts}",
                f"scan-like connection states (S0/REJ/RST...): {n_scanlike}",
            ]
            severity = "medium"
            if n_ports >= PORT_THRESHOLD and n_scanlike > n_ports // 2:
                severity = "high"
            findings.append(
                Finding(
                    id="port-scan",
                    title=f"Port/host scan from {src}",
                    severity=severity,
                    description=(
                        "A single source contacted an unusually large number of "
                        "ports or hosts, with many connections never completing. "
                        "This is consistent with network/service discovery."
                    ),
                    mitre=["T1046"],
                    evidence=evidence,
                    source_log="conn",
                    hosts=[src],
                )
            )

    return findings
