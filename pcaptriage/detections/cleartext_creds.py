"""Detect credentials sent over cleartext protocols."""

from __future__ import annotations

from typing import Dict, List

from .base import Finding, register

# Ports/services that carry credentials without encryption.
CLEARTEXT_SERVICES = {
    21: "FTP",
    23: "Telnet",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    25: "SMTP",
}


@register
def detect_cleartext_creds(logs: Dict[str, List[dict]]) -> List[Finding]:
    findings: List[Finding] = []
    evidence: List[str] = []

    # FTP: Zeek ftp.log carries 'user' and 'password'.
    for rec in logs.get("ftp", []):
        user = rec.get("user")
        pw = rec.get("password")
        if user:
            src = rec.get("id.orig_h", "?")
            dst = rec.get("id.resp_h", "?")
            shown_pw = pw if pw else "(captured)"
            evidence.append(f"FTP {src} -> {dst} login user={user} password={shown_pw}")

    # HTTP basic auth: Zeek http.log exposes 'username' (and 'password').
    for rec in logs.get("http", []):
        user = rec.get("username")
        if user:
            src = rec.get("id.orig_h", "?")
            host = rec.get("host", rec.get("id.resp_h", "?"))
            uri = rec.get("uri", "")
            evidence.append(f"HTTP basic auth {src} -> {host}{uri} user={user}")

    # Any session on a cleartext service, from conn.log (coarse signal).
    cleartext_sessions = 0
    for rec in logs.get("conn", []):
        port = rec.get("id.resp_p")
        if port in CLEARTEXT_SERVICES:
            cleartext_sessions += 1

    if evidence:
        findings.append(
            Finding(
                id="cleartext-creds",
                title="Credentials transmitted in cleartext",
                severity="high",
                description=(
                    "Login credentials were observed over an unencrypted protocol. "
                    "Anyone on the path can capture them. Move the service to a "
                    "TLS-protected equivalent (FTPS/SFTP, HTTPS, IMAPS...)."
                ),
                mitre=["T1552", "T1040"],
                evidence=evidence[:25],
                source_log="ftp/http",
            )
        )
    elif cleartext_sessions:
        findings.append(
            Finding(
                id="cleartext-services",
                title="Cleartext services in use",
                severity="low",
                description=(
                    f"{cleartext_sessions} session(s) used a cleartext protocol "
                    "(FTP/Telnet/HTTP/POP3/IMAP/SMTP). No credentials were parsed, "
                    "but traffic is exposed to sniffing."
                ),
                mitre=["T1040"],
                evidence=[],
                source_log="conn",
            )
        )

    return findings
