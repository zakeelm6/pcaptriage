"""Profile of every external server that a finding points at.

The questions an analyst asks next are always the same: what is this address
called, when was it first contacted, what software does it run, what
certificate does it present, and which detection flagged it. The answers are
already in the Zeek logs, scattered over five files. This gathers them.

Nothing here leaves the machine: reputation lookups (VirusTotal and so on) are
left to the analyst, with the address and domain ready to copy.
"""

from __future__ import annotations

import ipaddress
from collections import Counter, defaultdict
from typing import Dict, List

from .detections.base import Finding, fmt_ts


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _ordered(items) -> List[str]:
    seen, out = set(), []
    for i in items:
        if i and i not in seen:
            seen.add(i)
            out.append(i)
    return out


def build_indicators(logs: Dict[str, List[dict]], findings: List[Finding]) -> List[dict]:
    flagged_by: Dict[str, List[str]] = defaultdict(list)
    for f in findings:
        for ip in f.servers:
            if f.id not in flagged_by[ip]:
                flagged_by[ip].append(f.id)
    if not flagged_by:
        return []

    names: Dict[str, List[str]] = defaultdict(list)
    for rec in logs.get("dns", []):
        answers = [a for a in (rec.get("answers") or []) if isinstance(a, str)]
        for a in answers:
            if _is_ip(a) and a in flagged_by and rec.get("query"):
                names[a].append(rec["query"].lower())
    for rec in logs.get("http", []):
        ip = rec.get("id.resp_h")
        if ip in flagged_by and rec.get("host"):
            names[ip].append(rec["host"].lower().split(":")[0])
    for rec in logs.get("ssl", []):
        ip = rec.get("id.resp_h")
        if ip in flagged_by and rec.get("server_name"):
            names[ip].append(rec["server_name"].lower())

    first: Dict[str, float] = {}
    for rec in logs.get("conn", []):
        ip, ts = rec.get("id.resp_h"), rec.get("ts")
        if ip in flagged_by and ts is not None and (ip not in first or ts < first[ip]):
            first[ip] = ts

    software: Dict[str, Dict[str, Counter]] = defaultdict(lambda: defaultdict(Counter))
    for rec in logs.get("pcaptriage_http", []):
        ip = rec.get("resp_h")
        if ip in flagged_by and rec.get("name") and rec.get("value"):
            software[ip][rec["name"]][rec["value"]] += 1

    x509 = {r["fingerprint"]: r for r in logs.get("x509", []) if r.get("fingerprint")}
    tls: Dict[str, dict] = {}
    for rec in logs.get("ssl", []):
        ip = rec.get("id.resp_h")
        fps = rec.get("cert_chain_fps") or []
        if ip in flagged_by and ip not in tls and fps and fps[0] in x509:
            leaf = x509[fps[0]]
            tls[ip] = {"subject": leaf.get("certificate.subject", ""),
                       "issuer": leaf.get("certificate.issuer", "")}

    out = []
    for ip, ids in flagged_by.items():
        sw = software.get(ip, {})
        out.append(
            {
                "ip": ip,
                "names": _ordered(names.get(ip, [])),
                "first_seen": fmt_ts(first[ip]) if ip in first else "",
                "_first_ts": first.get(ip, 0),
                "server_header": sw.get("SERVER", Counter()).most_common(1)[0][0] if sw.get("SERVER") else "",
                "powered_by": sw.get("X-POWERED-BY", Counter()).most_common(1)[0][0] if sw.get("X-POWERED-BY") else "",
                "tls_subject": tls.get(ip, {}).get("subject", ""),
                "tls_issuer": tls.get(ip, {}).get("issuer", ""),
                "flagged_by": ids,
            }
        )
    out.sort(key=lambda d: d["_first_ts"])
    for d in out:
        d.pop("_first_ts")
    return out
