"""Detect an HTTP Host header that does not match the name the server was resolved from.

A client normally resolves a name, then connects to the resulting IP and sends
that same name in the Host header. When the Host header names a *different*
site than the one that resolved to this IP, the request is lying about where
it goes. Command-and-control frameworks do this on purpose (malleable profiles
that pretend to be a certificate-authority OCSP/CRL service, domain fronting),
so the traffic looks harmless to a glance at the proxy log.

Only IPs for which the capture contains a DNS answer are judged: if the client
never resolved the IP in this capture (cached lookup, hard-coded address) we
have nothing to compare against, so we stay silent rather than guess.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from typing import Dict, List, Set, Tuple

from .base import Finding, fmt_ts, register
from .suspicious_download import is_external

# A single odd request can be a proxy or a cache. A series is a pattern.
MIN_REQUESTS = 3


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _site(name: str) -> str:
    """Rough registrable domain: the last two labels. Good enough for triage."""
    labels = name.lower().rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name.lower()


@register
def detect_host_mismatch(logs: Dict[str, List[dict]]) -> List[Finding]:
    http, dns = logs.get("http", []), logs.get("dns", [])
    if not http or not dns:
        return []

    # IP -> every name it was resolved from (the query and any CNAME in the answer).
    names_for_ip: Dict[str, Set[str]] = defaultdict(set)
    resolved: Set[str] = set()
    for rec in dns:
        query = (rec.get("query") or "").lower().rstrip(".")
        answers = [a for a in (rec.get("answers") or []) if isinstance(a, str)]
        if not query or not answers:
            continue
        resolved.add(query)
        names = {query} | {a.lower().rstrip(".") for a in answers if not _is_ip(a)}
        resolved.update(names)
        for a in answers:
            if _is_ip(a):
                names_for_ip[a].update(names)

    groups: Dict[Tuple[str, str, str], List[float]] = defaultdict(list)
    for rec in http:
        client, server = rec.get("id.orig_h"), rec.get("id.resp_h")
        host = (rec.get("host") or "").lower().split(":")[0].rstrip(".")
        if not (client and server and host) or _is_ip(host) or not is_external(server):
            continue
        known = names_for_ip.get(server)
        if not known:                       # never resolved here: nothing to compare
            continue
        if host in known or _site(host) in {_site(n) for n in known}:
            continue
        groups[(client, server, host)].append(rec.get("ts", 0))

    findings: List[Finding] = []
    for (client, server, host), ts in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        if len(ts) < MIN_REQUESTS:
            continue
        real = sorted(names_for_ip[server])
        never = host not in resolved
        findings.append(
            Finding(
                id="http-host-mismatch",
                title=f"HTTP Host '{host}' sent to an IP that resolved from another site",
                severity="high" if never else "medium",
                description=(
                    f"{client} sent {len(ts)} requests with 'Host: {host}' to {server}, "
                    f"but that address was resolved from {', '.join(real)}. The request "
                    "claims one site and goes to another, which is how command-and-control "
                    "traffic disguises itself as a legitimate service (certificate "
                    "revocation checks, CDN fronting)."
                    + (f" '{host}' was never even resolved in this capture." if never else "")
                ),
                mitre=["T1090.004", "T1071.001"],
                evidence=[
                    f"client: {client}",
                    f"destination: {server}",
                    f"Host header sent: {host} ({len(ts)} requests)",
                    f"name(s) this IP actually resolved from: {', '.join(real)}",
                    f"Host header ever resolved in this capture: {'no' if never else 'yes, to other addresses'}",
                    f"first request: {fmt_ts(min(ts))}",
                    f"last request: {fmt_ts(max(ts))}",
                ],
                source_log="http/dns",
                hosts=[client],
                servers=[server],
            )
        )
    return findings
