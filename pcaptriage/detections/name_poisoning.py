"""Detect LLMNR/NBT-NS/mDNS name-resolution poisoning (Responder-style)."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from .base import Finding, register

# UDP ports used by broadcast/multicast name resolution.
NAME_RES_PORTS = {5355: "LLMNR", 137: "NBT-NS", 5353: "mDNS"}

# Multicast/broadcast destinations these queries normally go to.
MULTICAST_PREFIXES = ("224.", "ff02:", "239.")

# A responder answering this many distinct victims looks like poisoning.
VICTIM_THRESHOLD = 3


def _is_multicast_or_broadcast(ip: str) -> bool:
    if not ip:
        return False
    return ip.startswith(MULTICAST_PREFIXES) or ip.endswith(".255") or ip == "255.255.255.255"


@register
def detect_name_poisoning(logs: Dict[str, List[dict]]) -> List[Finding]:
    conns = logs.get("conn", [])
    if not conns:
        return []

    # Hosts replying from a name-resolution port to distinct unicast victims.
    victims_by_responder: Dict[tuple, Set[str]] = defaultdict(set)
    # Overall presence of these protocols (for the low-severity hint).
    protocols_seen: Set[str] = set()

    for rec in conns:
        orig = rec.get("id.orig_h")
        resp = rec.get("id.resp_h")
        orig_p = rec.get("id.orig_p")
        resp_p = rec.get("id.resp_p")

        if resp_p in NAME_RES_PORTS or orig_p in NAME_RES_PORTS:
            proto = NAME_RES_PORTS.get(resp_p) or NAME_RES_PORTS.get(orig_p)
            protocols_seen.add(proto)

        # A unicast reply sourced from a name-resolution port is the poisoner
        # answering a victim's query.
        if orig_p in NAME_RES_PORTS and resp and not _is_multicast_or_broadcast(resp):
            victims_by_responder[(orig, NAME_RES_PORTS[orig_p])].add(resp)

    findings: List[Finding] = []
    flagged = False
    for (responder, proto), victims in sorted(
        victims_by_responder.items(), key=lambda kv: len(kv[1]), reverse=True
    ):
        if len(victims) >= VICTIM_THRESHOLD:
            flagged = True
            sample = ", ".join(sorted(victims)[:8])
            findings.append(
                Finding(
                    id="name-poisoning",
                    title=f"Possible {proto} poisoning from {responder}",
                    severity="high",
                    description=(
                        f"{responder} answered {proto} name-resolution queries for "
                        f"{len(victims)} distinct hosts. A single host replying to many "
                        "broadcast/multicast name queries is the signature of a "
                        "poisoning tool (e.g. Responder), often a precursor to NTLM "
                        "relay and credential theft."
                    ),
                    mitre=["T1557.001"],
                    evidence=[
                        f"responder: {responder}",
                        f"protocol: {proto}",
                        f"victims answered: {len(victims)}",
                        f"sample victims: {sample}",
                    ],
                    source_log="conn",
                )
            )

    if not flagged and protocols_seen:
        findings.append(
            Finding(
                id="name-resolution-exposed",
                title="Broadcast name resolution in use",
                severity="low",
                description=(
                    "Traffic uses "
                    + "/".join(sorted(protocols_seen))
                    + ". These protocols are commonly abused for poisoning and NTLM "
                    "relay. No single poisoner stood out here, but disabling LLMNR and "
                    "NBT-NS where possible reduces the attack surface."
                ),
                mitre=["T1557.001"],
                evidence=[],
                source_log="conn",
            )
        )

    return findings
