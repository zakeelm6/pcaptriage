"""Opt-in content decoding (Base64 / hex / URL-encoding).

In CTF and lab captures, payloads and flags are often just encoded, not
encrypted: Base64 in a DNS label, hex in a URI, URL-encoding in a POST.
This module scans the text fields Zeek already extracted, tries a few
reversible decodings, and surfaces anything that decodes to readable
content. It is opt-in (CLI --decode) because it is noisy by nature.

This is decoding, not decryption: it never needs a key. TLS decryption
(which does need key material) is a separate, future concern.
"""

from __future__ import annotations

import base64
import binascii
import re
from urllib.parse import unquote
from typing import Dict, List

from .detections.base import Finding

# Tokens worth trying to decode.
B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")

# Keywords that make a decoded string worth escalating.
INTERESTING = (
    "flag{", "flag:", "http://", "https://", "powershell", "cmd.exe",
    "/bin/", "invoke-", "-enc", "password", "passwd", "user=", "token",
    "ssh-rsa", "begin rsa", "base64",
)

# Zeek log -> fields whose string values we scan.
FIELDS = {
    "http": ("uri", "user_agent", "host", "referrer", "username"),
    "dns": ("query",),
    "ftp": ("arg", "command"),
}


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for c in b if 32 <= c <= 126 or c in (9, 10, 13))
    return printable / len(b)


def _looks_text(b: bytes) -> bool:
    return len(b) >= 4 and _printable_ratio(b) >= 0.85


def _try_decode(token: str):
    """Return (scheme, decoded_text) for the first decoding that yields text."""
    # Base64
    if B64_RE.fullmatch(token):
        pad = "=" * (-len(token) % 4)
        try:
            raw = base64.b64decode(token + pad, validate=True)
            if _looks_text(raw) and raw.decode("utf-8", "ignore") != token:
                return "base64", raw.decode("utf-8", "ignore")
        except (binascii.Error, ValueError):
            pass
    # Hex
    if HEX_RE.fullmatch(token) and len(token) % 2 == 0:
        try:
            raw = bytes.fromhex(token)
            if _looks_text(raw):
                return "hex", raw.decode("utf-8", "ignore")
        except ValueError:
            pass
    return None


def _iter_strings(logs: Dict[str, List[dict]]):
    """Yield (source, original_string) from the scanned fields."""
    for log_name, fields in FIELDS.items():
        for rec in logs.get(log_name, []):
            for field in fields:
                val = rec.get(field)
                if isinstance(val, str) and val:
                    yield log_name, val
            # dns answers can be a list
            if log_name == "dns":
                for ans in rec.get("answers", []) or []:
                    if isinstance(ans, str):
                        yield "dns", ans


def decode_findings(logs: Dict[str, List[dict]]) -> List[Finding]:
    hits = []           # (source, scheme, original, decoded)
    seen = set()

    for source, s in _iter_strings(logs):
        # Whole-string URL-decode first.
        if "%" in s:
            dec = unquote(s)
            if dec != s and dec not in seen:
                seen.add(dec)
                hits.append((source, "url", s, dec))

        # Then token-level base64/hex.
        for token in set(B64_RE.findall(s)) | set(HEX_RE.findall(s)):
            res = _try_decode(token)
            if res:
                scheme, decoded = res
                key = (scheme, decoded)
                if key not in seen:
                    seen.add(key)
                    hits.append((source, scheme, token, decoded))

    if not hits:
        return []

    def is_interesting(text: str) -> bool:
        low = text.lower()
        return any(k in low for k in INTERESTING)

    interesting = [h for h in hits if is_interesting(h[3])]
    evidence = [
        f"[{src}] {scheme}: {orig[:40]}{'...' if len(orig) > 40 else ''} -> {dec[:120]}"
        for (src, scheme, orig, dec) in (interesting or hits)[:30]
    ]

    severity = "high" if interesting else "info"
    title = (
        "Decoded content of interest (flags/commands/credentials)"
        if interesting
        else "Encoded content decoded"
    )
    desc = (
        "Reversible encodings were found and decoded in the capture "
        f"({len(hits)} item(s)). "
        + (
            "Some decoded to flags, commands or credentials, review below."
            if interesting
            else "No obviously sensitive content, but the raw decodings are listed."
        )
    )
    return [
        Finding(
            id="decoded-content",
            title=title,
            severity=severity,
            description=desc,
            mitre=["T1132", "T1027"],
            evidence=evidence,
            source_log="http/dns/ftp",
        )
    ]
