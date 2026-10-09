"""Flag TLS servers whose certificate looks like command-and-control infrastructure.

Zeek does not put the certificate in ssl.log. It logs the chain as
fingerprints (cert_chain_fps) and the certificates themselves in x509.log, so
the two are joined here. (An earlier version of this detector read fields that
only exist when an optional Zeek policy is loaded, so it never fired on a real
capture.)

Signals, each weak alone:
  * self-signed certificate
  * a validity period of many years (generated once, never renewed)
  * the server name asked for does not match the certificate
  * no SNI, and a certificate not issued by a recognisable public CA
  * an expired certificate

Mail ports are skipped: SMTP servers with self-signed certificates are normal
and would drown the signal.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List

from .base import Finding, fmt_ts, register
from .suspicious_download import is_external

MAIL_PORTS = {25, 110, 143, 465, 587, 993, 995}
LONG_LIVED_DAYS = 3000

# Substrings of issuer names we recognise as public or common CAs.
KNOWN_CA = (
    "let's encrypt", "isrg", "digicert", "godaddy", "go daddy", "sectigo", "comodo",
    "globalsign", "microsoft", "amazon", "google trust", "cloudflare", "entrust",
    "geotrust", "thawte", "verisign", "usertrust", "zerossl", "cpanel", "starfield",
    "baltimore", "identrust", "certum", "ssl.com", "buypass", "actalis", "quovadis",
    "telia", "swisssign", "harica", "rapidssl", "symantec", "network solutions",
    "apple", "adobe", "akamai",
)


def _known_ca(issuer: str) -> bool:
    low = (issuer or "").lower()
    return any(k in low for k in KNOWN_CA)


@register
def detect_suspicious_tls(logs: Dict[str, List[dict]]) -> List[Finding]:
    ssl = logs.get("ssl", [])
    if not ssl:
        return []
    x509 = {r["fingerprint"]: r for r in logs.get("x509", []) if r.get("fingerprint")}

    servers: Dict[tuple, dict] = {}
    for rec in ssl:
        server, port = rec.get("id.resp_h"), rec.get("id.resp_p")
        if not server or not is_external(server) or port in MAIL_PORTS:
            continue

        reasons = set()
        subject = issuer = ""
        status = (rec.get("validation_status") or "").lower()   # only if an optional policy is loaded
        if status and status != "ok":
            reasons.add("self-signed certificate" if "self signed" in status
                        else "expired certificate" if "expired" in status
                        else f"certificate does not validate ({status})")

        fps = rec.get("cert_chain_fps") or []
        leaf = x509.get(fps[0]) if fps else None
        if leaf:
            subject = leaf.get("certificate.subject", "")
            issuer = leaf.get("certificate.issuer", "")
            if subject and subject == issuer:
                reasons.add("self-signed certificate")
            nb, na = leaf.get("certificate.not_valid_before"), leaf.get("certificate.not_valid_after")
            if nb is not None and na is not None:
                days = (na - nb) / 86400
                if days >= LONG_LIVED_DAYS:
                    reasons.add(f"valid for {days:.0f} days")
                if rec.get("ts") is not None and na < rec["ts"]:
                    reasons.add("expired certificate")
            if not rec.get("server_name") and not _known_ca(issuer):
                reasons.add("no SNI and issuer is not a known public CA")
        if rec.get("sni_matches_cert") is False:
            reasons.add("server name does not match the certificate")

        if not reasons:
            continue
        s = servers.setdefault((server, port), {
            "reasons": set(), "clients": set(), "sni": set(), "issuer": "", "subject": "",
            "first": rec.get("ts"), "count": 0,
        })
        s["reasons"] |= reasons
        s["count"] += 1
        if rec.get("id.orig_h"):
            s["clients"].add(rec["id.orig_h"])
        if rec.get("server_name"):
            s["sni"].add(rec["server_name"])
        s["issuer"] = s["issuer"] or issuer
        s["subject"] = s["subject"] or subject
        if rec.get("ts") is not None and (s["first"] is None or rec["ts"] < s["first"]):
            s["first"] = rec["ts"]

    if not servers:
        return []

    evidence: List[str] = []
    clients, hosts = set(), []
    severe = False
    for (server, port), s in sorted(servers.items(), key=lambda kv: -len(kv[1]["reasons"])):
        severe = severe or "self-signed certificate" in s["reasons"] or len(s["reasons"]) >= 2
        clients |= s["clients"]
        hosts.append(server)
        when = f"[{fmt_ts(s['first'])}] " if s["first"] is not None else ""
        evidence.append(f"{when}{server}:{port} ({s['count']} sessions): " + "; ".join(sorted(s["reasons"])))
        if s["subject"]:
            evidence.append(f"    subject: {s['subject']}")
        if s["issuer"] and s["issuer"] != s["subject"]:
            evidence.append(f"    issuer:  {s['issuer']}")

    return [
        Finding(
            id="suspicious-tls",
            title="Suspicious TLS certificate(s)",
            severity="high" if severe else "medium",
            description=(
                "One or more external TLS servers presented a certificate with traits "
                "typical of command-and-control infrastructure (self-signed, years-long "
                "validity, no matching name, unknown issuer). Each trait is common alone "
                "in internal or test setups; together they are worth a look."
            ),
            mitre=["T1573"],
            evidence=evidence[:30],
            source_log="ssl/x509",
            hosts=sorted(clients),
            servers=hosts,
        )
    ]
