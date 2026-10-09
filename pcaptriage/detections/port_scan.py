"""Detect port scans and host sweeps from conn.log.

Counting how many hosts or ports a source touches is not enough: a busy
workstation talks to hundreds of web servers. What marks a scan is that the
connections mostly fail to complete, so every rule below also requires a
high share of scan-like connection states.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set, Tuple

from .base import Finding, register

# Port scan: a source tries this many distinct ports, and at least half of
# them end in a scan-like state (no reply, rejected, reset).
PORT_THRESHOLD = 50
# Host sweep: a source hits the same port on this many distinct hosts...
HOST_THRESHOLD = 25
# ...and this share of its connections to that port are scan-like.
SWEEP_RATIO = 0.7
# Connection states typical of scans (no payload / rejected / reset).
SCAN_STATES = {"S0", "REJ", "RSTR", "RSTOS0", "SH", "OTH"}


@register
def detect_port_scan(logs: Dict[str, List[dict]]) -> List[Finding]:
    conns = logs.get("conn", [])
    if not conns:
        return []

    ports_by_src: Dict[str, Set[int]] = defaultdict(set)
    scan_ports_by_src: Dict[str, Set[int]] = defaultdict(set)
    scanlike_by_src: Dict[str, int] = defaultdict(int)
    # Per (source, port): all connections, scan-like connections, scan-like hosts.
    total_sp: Dict[Tuple[str, int], int] = defaultdict(int)
    scan_sp: Dict[Tuple[str, int], int] = defaultdict(int)
    scan_hosts_sp: Dict[Tuple[str, int], Set[str]] = defaultdict(set)

    for rec in conns:
        src = rec.get("id.orig_h")
        dst = rec.get("id.resp_h")
        port = rec.get("id.resp_p")
        if src is None or port is None:
            continue
        scanlike = rec.get("conn_state", "") in SCAN_STATES
        ports_by_src[src].add(port)
        total_sp[(src, port)] += 1
        if scanlike:
            scanlike_by_src[src] += 1
            scan_ports_by_src[src].add(port)
            scan_sp[(src, port)] += 1
            if dst is not None:
                scan_hosts_sp[(src, port)].add(dst)

    findings: List[Finding] = []

    # 1. Port scan: many ports, mostly unanswered.
    for src, ports in sorted(ports_by_src.items(), key=lambda kv: len(kv[1]), reverse=True):
        n_ports = len(ports)
        n_scan_ports = len(scan_ports_by_src[src])
        if n_ports >= PORT_THRESHOLD and n_scan_ports >= n_ports // 2:
            findings.append(
                Finding(
                    id="port-scan",
                    title=f"Port scan from {src}",
                    severity="high",
                    description=(
                        "A single source tried a large number of ports and most "
                        "connections never completed. This is consistent with "
                        "service discovery."
                    ),
                    mitre=["T1046"],
                    evidence=[
                        f"source {src}",
                        f"distinct destination ports tried: {n_ports}",
                        f"ports ending in a scan-like state (S0/REJ/RST...): {n_scan_ports}",
                    ],
                    source_log="conn",
                    hosts=[src],
                )
            )

    # 2. Host sweep: the same port across many hosts, mostly unanswered.
    for (src, port), hosts in sorted(scan_hosts_sp.items(), key=lambda kv: len(kv[1]), reverse=True):
        total = total_sp[(src, port)]
        if len(hosts) >= HOST_THRESHOLD and scan_sp[(src, port)] / total >= SWEEP_RATIO:
            findings.append(
                Finding(
                    id="port-scan",
                    title=f"Host sweep from {src} on port {port}",
                    severity="medium",
                    description=(
                        f"{src} probed port {port} on many different hosts and most "
                        "attempts went unanswered. This is consistent with a sweep "
                        "looking for hosts running a given service."
                    ),
                    mitre=["T1046"],
                    evidence=[
                        f"source {src}, port {port}",
                        f"distinct hosts probed without a completed session: {len(hosts)}",
                        f"scan-like share of connections to this port: "
                        f"{scan_sp[(src, port)]}/{total}",
                    ],
                    source_log="conn",
                    hosts=[src],
                )
            )

    return findings
