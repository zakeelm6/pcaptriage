"""Flag suspicious TLS certificates from ssl.log."""

from __future__ import annotations

from collections import Counter
from typing import Dict, List

from .base import Finding, register

# Validation outcomes Zeek reports that are not a clean, trusted chain.
BAD_STATUSES = {
    "self signed certificate",
    "self signed certificate in certificate chain",
    "unable to get local issuer certificate",
    "certificate has expired",
    "unable to verify the first certificate",
}


@register
def detect_suspicious_tls(logs: Dict[str, List[dict]]) -> List[Finding]:
    ssl = logs.get("ssl", [])
    if not ssl:
        return []

    evidence: List[str] = []
    reasons: Counter = Counter()
    hosts: set = set()

    for rec in ssl:
        status = (rec.get("validation_status") or "").lower()
        subject = rec.get("subject", "")
        server = rec.get("server_name", "")
        src = rec.get("id.orig_h")
        dst = rec.get("id.resp_h", "?")
        dport = rec.get("id.resp_p", "?")
        if status and status != "ok" and (status in BAD_STATUSES or "self signed" in status or "expired" in status):
            reasons[status] += 1
            label = server or subject or "(no SNI/subject)"
            evidence.append(f"{dst}:{dport} {label} -> {status}")
            if src:
                hosts.add(src)

    if not evidence:
        return []

    # Self-signed on an unusual port is a stronger C2 signal than a plain
    # expired cert on 443.
    severity = "medium"
    if any("self signed" in r for r in reasons):
        severity = "high"

    reason_summary = ", ".join(f"{n}x {r}" for r, n in reasons.most_common())
    return [
        Finding(
            id="suspicious-tls",
            title="Suspicious TLS certificate(s)",
            severity=severity,
            description=(
                "One or more TLS sessions used certificates that do not validate "
                "against a trusted chain (self-signed, expired, or unknown issuer). "
                "Benign in internal/dev setups, but also typical of malware C2 and "
                "interception. Summary: " + reason_summary
            ),
            mitre=["T1573"],
            evidence=evidence[:25],
            source_log="ssl",
            hosts=sorted(hosts),
        )
    ]
