"""List the new domains a host contacted right after it downloaded a suspicious file.

Delivery is rarely the end: the dropped file fetches its next stage from other
servers within seconds or minutes. Those follow-up domains are often the only
hint left when the second stage travels over HTTPS and cannot be read.

This is context, not a verdict: a person browsing after a download would also
show up. Names belonging to well-known operating-system and update
infrastructure are left out to keep the list short. It only runs when a
suspicious download was found, and it is reported at "info" severity.
"""

from __future__ import annotations

from typing import Dict, List

from .base import Finding, fmt_ts, register
from .suspicious_download import detect_suspicious_download

WINDOW_SECONDS = 300
MAX_LISTED = 15

# Suffixes of names we do not list: platform and update infrastructure.
BENIGN_SUFFIXES = (
    "microsoft.com", "windows.com", "windows.net", "windowsupdate.com", "msedge.net",
    "azureedge.net", "bing.com", "live.com", "office.com", "office365.com", "office.net",
    "skype.com", "msn.com", "msftncsi.com", "msftconnecttest.com", "msauth.net",
    "onedrive.com", "xboxlive.com", "microsoftonline.com", "trafficmanager.net", "cloudapp.net", "sfx.ms",
    "digicert.com", "lencr.org", "verisign.com", "apple.com", "icloud.com",
    "google.com", "gstatic.com", "googleapis.com", "mozilla.org", "mozilla.net",
    "firefox.com", "adobe.com", "akamai.net", "akamaiedge.net", "akamaihd.net",
    "edgekey.net", "nelreports.net",
)
LOCAL_SUFFIXES = (".local", ".lan", ".home", ".internal", ".arpa", ".localdomain")


def _skip(name: str) -> bool:
    return (
        "." not in name
        or name.endswith(LOCAL_SUFFIXES)
        or any(name == s or name.endswith("." + s) for s in BENIGN_SUFFIXES)
    )


@register
def detect_post_delivery(logs: Dict[str, List[dict]]) -> List[Finding]:
    dns = logs.get("dns", [])
    downloads = detect_suspicious_download(logs)
    if not dns or not downloads:
        return []

    # Earliest download per client, and the domains it came from.
    start: Dict[str, float] = {}
    source: Dict[str, set] = {}
    for ev in downloads[0].data.get("events", []):
        client, ts = ev.get("client"), ev.get("ts")
        if client and ts is not None and (client not in start or ts < start[client]):
            start[client] = ts
        if client and ev.get("domain"):
            source.setdefault(client, set()).add(ev["domain"].lower())

    findings: List[Finding] = []
    for client, t0 in start.items():
        seen: Dict[str, tuple] = {}
        for rec in sorted(dns, key=lambda r: r.get("ts", 0)):
            ts = rec.get("ts")
            name = (rec.get("query") or "").lower().rstrip(".")
            if (rec.get("id.orig_h") != client or ts is None or not (t0 <= ts <= t0 + WINDOW_SECONDS)
                    or not name or name in seen or name in source.get(client, set())
                    or rec.get("qtype_name") not in ("A", "AAAA") or name.startswith("_")
                    or not rec.get("answers") or _skip(name)):
                continue
            ips = [a for a in rec["answers"] if isinstance(a, str) and a[:1].isdigit()]
            seen[name] = (ts, ips)
        if not seen:
            continue
        listed = list(seen.items())[:MAX_LISTED]
        findings.append(
            Finding(
                id="post-delivery-contacts",
                title=f"New domains contacted within {WINDOW_SECONDS // 60} minutes of the download",
                severity="info",
                description=(
                    f"After {client} downloaded a suspicious file, it resolved these names, "
                    "leaving out well-known platform and update domains. Follow-up stages "
                    "are often fetched from such servers, including over HTTPS where the "
                    "content cannot be read. This is context to review, not a verdict."
                ),
                mitre=["T1105"],
                evidence=[f"[{fmt_ts(ts)}] {name} -> {', '.join(ips) or '(no address)'}"
                          for name, (ts, ips) in listed],
                source_log="dns",
                hosts=[client],
            )
        )
    return findings
