"""Detect possible DNS tunneling / exfiltration from dns.log."""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List

from .base import Finding, register

# A registered domain seen more than this many times is worth a look.
QUERY_COUNT_THRESHOLD = 100
# Average queried-name length above this suggests encoded data.
AVG_LEN_THRESHOLD = 40
# Shannon entropy above this suggests encoded/compressed subdomains.
ENTROPY_THRESHOLD = 3.5


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _registered_domain(qname: str) -> str:
    """Rough eTLD+1: last two labels. Good enough for triage."""
    labels = qname.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else qname


@register
def detect_dns_tunneling(logs: Dict[str, List[dict]]) -> List[Finding]:
    dns = logs.get("dns", [])
    if not dns:
        return []

    count_by_domain: Dict[str, int] = defaultdict(int)
    len_sum_by_domain: Dict[str, int] = defaultdict(int)
    ent_sum_by_domain: Dict[str, float] = defaultdict(float)

    for rec in dns:
        qname = rec.get("query")
        if not qname:
            continue
        dom = _registered_domain(qname)
        # Measure the part below the registered domain (the subdomain).
        sub = qname[: -len(dom)].rstrip(".") if qname.endswith(dom) else qname
        count_by_domain[dom] += 1
        len_sum_by_domain[dom] += len(qname)
        ent_sum_by_domain[dom] += _entropy(sub)

    findings: List[Finding] = []
    for dom, count in sorted(count_by_domain.items(), key=lambda kv: kv[1], reverse=True):
        if count < QUERY_COUNT_THRESHOLD:
            continue
        avg_len = len_sum_by_domain[dom] / count
        avg_ent = ent_sum_by_domain[dom] / count
        if avg_len >= AVG_LEN_THRESHOLD or avg_ent >= ENTROPY_THRESHOLD:
            severity = "high" if (avg_len >= AVG_LEN_THRESHOLD and avg_ent >= ENTROPY_THRESHOLD) else "medium"
            findings.append(
                Finding(
                    id="dns-tunneling",
                    title=f"Possible DNS tunneling via {dom}",
                    severity=severity,
                    description=(
                        "A single domain received a high volume of queries with long "
                        "and/or high-entropy names. This pattern is consistent with "
                        "data encoded into DNS (tunneling or exfiltration)."
                    ),
                    mitre=["T1071.004", "T1048"],
                    evidence=[
                        f"domain: {dom}",
                        f"query count: {count}",
                        f"average query length: {avg_len:.1f}",
                        f"average subdomain entropy: {avg_ent:.2f}",
                    ],
                    source_log="dns",
                )
            )

    return findings
