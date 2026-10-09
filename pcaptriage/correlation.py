"""Correlate findings into an attack narrative.

Individual detections answer "what happened". This layer answers
"is this a chain?" by pivoting findings on the hosts they involve and
ordering them along a simplified kill chain. A single host that shows
up across several phases is the strongest signal of a real compromise,
and that story is what pcaptriage shows that raw Zeek/Suricata output
does not.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .detections.base import Finding

# Simplified kill-chain phases, in order.
PHASE_ORDER = [
    "Delivery",
    "Reconnaissance",
    "Credential Access",
    "Command & Control",
    "Propagation",
    "Exfiltration",
]

# Map each detection id to a phase.
PHASE_BY_ID = {
    "suspicious-download": "Delivery",
    "post-delivery-contacts": "Delivery",
    "mass-mailing": "Propagation",
    "port-scan": "Reconnaissance",
    "name-poisoning": "Credential Access",
    "name-resolution-exposed": "Credential Access",
    "cleartext-creds": "Credential Access",
    "cleartext-services": "Credential Access",
    "suspicious-tls": "Command & Control",
    "beaconing": "Command & Control",
    "http-host-mismatch": "Command & Control",
    "dns-tunneling": "Exfiltration",
}


def build_narrative(findings: List[Finding]) -> List[dict]:
    """Return per-host attack chains, strongest (most phases) first.

    Each chain: {host, phases: [ordered phase names], steps: {phase: [titles]}}.
    Only hosts spanning two or more phases are reported as a chain.
    """
    host_phase_titles: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))

    for f in findings:
        phase = PHASE_BY_ID.get(f.id)
        if not phase:
            continue
        for host in f.hosts:
            host_phase_titles[host][phase].append(f.title)

    chains: List[dict] = []
    for host, phase_titles in host_phase_titles.items():
        if len(phase_titles) < 2:
            continue
        ordered = [p for p in PHASE_ORDER if p in phase_titles]
        chains.append(
            {
                "host": host,
                "phases": ordered,
                "steps": {p: phase_titles[p] for p in ordered},
            }
        )

    chains.sort(key=lambda c: len(c["phases"]), reverse=True)
    return chains
