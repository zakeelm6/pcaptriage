"""Opt-in content decoding (several reversible schemes).

In CTF and lab captures, payloads and flags are often just encoded, not
encrypted: Base64 in a DNS label, hex in a URI, URL-encoding in a POST,
sometimes gzip-compressed on top. This module scans the text fields Zeek
already extracted and tries a selectable set of reversible decodings,
surfacing anything that decodes to readable content.

It is opt-in (CLI --decode) because it is noisy by nature, and the set of
schemes is configurable (--decode-schemes). This is decoding, not
decryption: it never needs a key. TLS decryption (which does need key
material) is a separate, future concern.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import zlib
from urllib.parse import unquote
from typing import Dict, List, Optional, Tuple

# Every scheme offered. "all" selects all of them.
ALL_SCHEMES = ["base64", "base32", "base85", "hex", "url", "rot13", "gzip"]
# Default set. base85 is excluded: its alphabet overlaps URI punctuation
# (? = < > ...), so it cannot be reliably delimited inside a URI and is
# noisy. Enable it explicitly (best on fields that are a pure blob).
DEFAULT_SCHEMES = ["base64", "base32", "hex", "url", "rot13", "gzip"]

# Keywords that make a decoded string worth escalating.
INTERESTING = (
    "flag{", "flag:", "ctf{", "http://", "https://", "powershell", "cmd.exe",
    "/bin/", "invoke-", "-enc", "password", "passwd", "user=", "token",
    "ssh-rsa", "begin rsa", "secret",
)

# Zeek log -> fields whose string values we scan.
FIELDS = {
    "http": ("uri", "user_agent", "host", "referrer", "username"),
    "dns": ("query",),
    "ftp": ("arg", "command"),
}

# Per-scheme candidate substrings, so a blob embedded in a URI
# (e.g. /a?x=<base64>) is still found without its surrounding path.
CANDIDATE_RE = {
    "base64": re.compile(r"[A-Za-z0-9+/]{16,}={0,2}"),
    "base32": re.compile(r"[A-Z2-7]{16,}={0,8}"),
    "base85": re.compile(r"[0-9A-Za-z!#$%&()*+;<=>?@^_`{|}~.-]{20,}"),
    "hex": re.compile(r"[0-9a-fA-F]{16,}"),
}


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    printable = sum(1 for c in b if 32 <= c <= 126 or c in (9, 10, 13))
    return printable / len(b)


def _looks_text(b: bytes) -> bool:
    return len(b) >= 4 and _printable_ratio(b) >= 0.85


def _b(raw: bytes) -> str:
    return raw.decode("utf-8", "ignore")


# --- transport decoders: str token -> bytes (or None) -----------------------

def _d_base64(tok: str) -> Optional[bytes]:
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", tok):
        return None
    try:
        return base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None


def _d_base32(tok: str) -> Optional[bytes]:
    if not re.fullmatch(r"[A-Z2-7]+={0,8}", tok):
        return None
    try:
        return base64.b32decode(tok + "=" * (-len(tok) % 8))
    except (binascii.Error, ValueError):
        return None


def _d_base85(tok: str) -> Optional[bytes]:
    try:
        return base64.b85decode(tok)
    except (ValueError, Exception):  # noqa: BLE001 - b85decode raises ValueError
        return None


def _d_hex(tok: str) -> Optional[bytes]:
    if len(tok) % 2 or not re.fullmatch(r"[0-9a-fA-F]+", tok):
        return None
    try:
        return bytes.fromhex(tok)
    except ValueError:
        return None


TRANSPORTS = {
    "base64": _d_base64,
    "base32": _d_base32,
    "base85": _d_base85,
    "hex": _d_hex,
}


def _maybe_gunzip(raw: bytes) -> Optional[bytes]:
    for wbits in (zlib.MAX_WBITS | 16, zlib.MAX_WBITS):  # gzip, then zlib
        try:
            out = zlib.decompress(raw, wbits)
            if out:
                return out
        except zlib.error:
            continue
    return None


VOWELS = set("aeiouyAEIOUY")
WORD_RE = re.compile(r"[A-Za-z]{3,}")


def _is_meaningful(text: str) -> bool:
    """Noise filter: does the decoded text look like real content, not
    the printable-but-random junk you get from decoding the wrong thing?"""
    t = text.strip()
    if len(t) < 4:
        return False
    if any(k in t.lower() for k in INTERESTING):
        return True
    letters = sum(c.isalpha() for c in t)
    if letters / len(t) < 0.45:          # mostly symbols/digits -> junk
        return False
    if not WORD_RE.search(t):            # no real word -> junk
        return False
    if not any(c in VOWELS for c in t):  # no vowels at all -> likely random
        return False
    return True


def _keep(text: str, strict: bool) -> bool:
    low = text.lower()
    if strict:
        return any(k in low for k in INTERESTING)
    return any(k in low for k in INTERESTING) or _is_meaningful(text)


def _iter_strings(logs: Dict[str, List[dict]]):
    for log_name, fields in FIELDS.items():
        for rec in logs.get(log_name, []):
            for field in fields:
                val = rec.get(field)
                if isinstance(val, str) and val:
                    yield log_name, val
            if log_name == "dns":
                for ans in rec.get("answers", []) or []:
                    if isinstance(ans, str):
                        yield "dns", ans


def normalize_schemes(schemes: Optional[List[str]]) -> List[str]:
    if not schemes:
        return list(DEFAULT_SCHEMES)
    if "all" in schemes:
        return list(ALL_SCHEMES)
    return [s for s in schemes if s in ALL_SCHEMES]


def decode_findings(logs: Dict[str, List[dict]], schemes: Optional[List[str]] = None,
                    strict: bool = False):
    from .detections.base import Finding

    schemes = normalize_schemes(schemes)
    hits: List[Tuple[str, str, str, str]] = []   # (source, scheme, original, decoded)
    seen = set()

    def add(source, scheme, orig, decoded, needs_keyword=False):
        # ROT13 turns any readable text into other readable-looking text, so
        # "looks like words" proves nothing: only a keyword hit is evidence.
        if needs_keyword or strict:
            if not any(k in decoded.lower() for k in INTERESTING):
                return
        elif not _keep(decoded, strict):
            return
        if (scheme, decoded) in seen:
            return
        seen.add((scheme, decoded))
        hits.append((source, scheme, orig, decoded))

    for source, s in _iter_strings(logs):
        # Whole-string transforms.
        if "url" in schemes and "%" in s:
            dec = unquote(s)
            if dec != s:
                add(source, "url", s, dec)
        if "rot13" in schemes:
            rot = codecs.decode(s, "rot_13")
            if rot != s:
                add(source, "rot13", s, rot, needs_keyword=True)

        # Token-level transport decoders, per-scheme candidate substrings.
        for name in schemes:
            regex = CANDIDATE_RE.get(name)
            if regex is None:
                continue
            fn = TRANSPORTS[name]
            # Regex substrings, plus the whole trimmed value (so a field that
            # is itself one clean blob decodes even when its alphabet is hard
            # to delimit, e.g. base85).
            candidates = set(regex.findall(s))
            if s.strip() and not any(c.isspace() for c in s.strip()):
                candidates.add(s.strip())
            for cand in candidates:
                raw = fn(cand)
                if raw is None:
                    continue
                if _looks_text(raw) and _b(raw) != cand:
                    add(source, name, cand, _b(raw))
                elif "gzip" in schemes:
                    un = _maybe_gunzip(raw)
                    if un and _looks_text(un):
                        add(source, f"{name}+gzip", cand, _b(un))

    if not hits:
        return []

    def interesting(text: str) -> bool:
        low = text.lower()
        return any(k in low for k in INTERESTING)

    flagged = [h for h in hits if interesting(h[3])]
    show = flagged or hits
    evidence = [
        f"[{src}] {scheme}: {orig[:36]}{'...' if len(orig) > 36 else ''} -> {dec[:120]}"
        for (src, scheme, orig, dec) in show[:40]
    ]

    severity = "high" if flagged else "info"
    title = (
        "Decoded content of interest (flags/commands/credentials)"
        if flagged
        else "Encoded content decoded"
    )
    desc = (
        f"Reversible encodings were found and decoded ({len(hits)} item(s), "
        f"schemes: {', '.join(schemes)}). "
        + (
            "Some decoded to flags, commands or credentials, review below."
            if flagged
            else "Nothing obviously sensitive, raw decodings listed."
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
