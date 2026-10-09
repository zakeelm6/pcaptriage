"""Detect an internal host sending mail to many external servers (malspam)."""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Set

from .base import Finding, decode_mime_words, fmt_ts, register
from .suspicious_download import RISKY, is_external

# A normal client talks to one mail relay. Many distinct external mail
# servers from a single workstation is the mark of spam/malspam.
SERVER_THRESHOLD = 10
HIGH_THRESHOLD = 20


@register
def detect_mass_mailing(logs: Dict[str, List[dict]]) -> List[Finding]:
    smtp = logs.get("smtp", [])
    if not smtp:
        return []

    servers: Dict[str, Set[str]] = defaultdict(set)
    sessions: Dict[str, int] = defaultdict(int)
    first_seen: Dict[str, float] = {}
    for rec in smtp:
        src, dst = rec.get("id.orig_h"), rec.get("id.resp_h")
        if src and dst and is_external(dst):
            servers[src].add(dst)
            sessions[src] += 1
            ts = rec.get("ts")
            if ts is not None and (src not in first_seen or ts < first_seen[src]):
                first_seen[src] = ts

    # Archives/executables attached to outgoing mail, per sending host.
    attachments: Dict[str, List[str]] = defaultdict(list)
    for rec in logs.get("files", []):
        if rec.get("source") == "SMTP" and rec.get("is_orig") and rec.get("mime_type") in RISKY:
            attachments[rec.get("id.orig_h", "")].append(
                f"{decode_mime_words(rec.get('filename') or '(unnamed)')} ({rec.get('mime_type')})"
            )

    findings: List[Finding] = []
    for src, dsts in sorted(servers.items(), key=lambda kv: len(kv[1]), reverse=True):
        if len(dsts) < SERVER_THRESHOLD:
            continue
        evidence = [
            f"sender: {src}",
            f"SMTP sessions to external servers: {sessions[src]}",
            f"distinct external mail servers: {len(dsts)}",
            *([f"first session: {fmt_ts(first_seen[src])}"] if src in first_seen else []),
            f"sample servers: {', '.join(sorted(dsts)[:6])}",
        ]
        atts = attachments.get(src, [])
        if atts:
            evidence.append(f"archive/executable attachments sent: {len(atts)}")
            evidence.extend(f"  attachment: {a}" for a in atts[:6])
        findings.append(
            Finding(
                id="mass-mailing",
                title=f"Mass mailing from {src} (possible malspam)",
                severity="high" if len(dsts) >= HIGH_THRESHOLD or atts else "medium",
                description=(
                    f"{src} opened SMTP sessions with {len(dsts)} different external mail "
                    "servers. A workstation normally uses a single relay, so this looks "
                    "like a compromised host sending spam or malicious mail to new victims."
                ),
                mitre=["T1566"],
                evidence=evidence,
                source_log="smtp/files",
                hosts=[src],
            )
        )
    return findings
