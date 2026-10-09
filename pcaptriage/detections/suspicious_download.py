"""Flag executables and archives downloaded over plain HTTP from the internet."""

from __future__ import annotations

import ipaddress
from typing import Dict, List

from .base import Finding, SEVERITY_ORDER, fmt_ts, register

# MIME type -> (kind, severity). Zeek identifies the type from the content,
# not from the file name, so a renamed payload is still caught.
RISKY = {
    "application/x-dosexec": ("executable", "high"),
    "application/x-msdownload": ("executable", "high"),
    "application/x-msdos-program": ("executable", "high"),
    "application/x-executable": ("executable", "high"),
    "application/x-elf": ("executable", "high"),
    "application/zip": ("archive", "medium"),
    "application/x-rar": ("archive", "medium"),
    "application/x-rar-compressed": ("archive", "medium"),
    "application/x-7z-compressed": ("archive", "medium"),
    "application/vnd.ms-cab-compressed": ("archive", "medium"),
    "application/java-archive": ("archive", "medium"),
}


def is_external(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


@register
def detect_suspicious_download(logs: Dict[str, List[dict]]) -> List[Finding]:
    files = logs.get("files", [])
    if not files:
        return []

    http_by_uid = {r["uid"]: r for r in logs.get("http", []) if r.get("uid")}
    evidence: List[str] = []
    hosts = set()
    worst = "medium"
    kinds = set()

    for rec in files:
        # HTTP responses only (is_orig False = the server sent it to the client).
        if rec.get("source") != "HTTP" or rec.get("is_orig"):
            continue
        mime = rec.get("mime_type")
        if mime not in RISKY:
            continue
        server = rec.get("id.resp_h", "")
        client = rec.get("id.orig_h", "")
        if not is_external(server):
            continue

        kind, sev = RISKY[mime]
        kinds.add(kind)
        if SEVERITY_ORDER[sev] > SEVERITY_ORDER[worst]:
            worst = sev
        http = http_by_uid.get(rec.get("uid"), {})
        uri = http.get("uri", "")
        where = f"{http.get('host') or server}{uri}"
        name = rec.get("filename") or uri.rsplit("/", 1)[-1] or "(unnamed)"
        when = f"[{fmt_ts(rec['ts'])}] " if rec.get("ts") is not None else ""
        evidence.append(
            f"{when}{client} downloaded {name} ({mime}, {rec.get('seen_bytes', '?')} bytes) "
            f"from {where} [{server}]"
        )
        if client:
            hosts.add(client)

    if not evidence:
        return []

    return [
        Finding(
            id="suspicious-download",
            title="Executable or archive downloaded over HTTP from the internet",
            severity=worst,
            description=(
                "A host fetched an " + " and ".join(sorted(kinds)) + " from an external "
                "server over unencrypted HTTP. This is how many infections start "
                "(a phishing link leading to a payload). It is often benign (software "
                "downloads), so check the source domain and what ran afterwards."
            ),
            mitre=["T1105"],
            evidence=evidence[:25],
            source_log="files/http",
            hosts=sorted(hosts),
        )
    ]
