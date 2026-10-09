"""Finding model and detection registry."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Callable, Dict, List

SEVERITY_ORDER = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}


@dataclass
class Finding:
    id: str                      # stable slug, e.g. "cleartext-creds"
    title: str
    severity: str                # one of SEVERITY_ORDER keys
    description: str
    mitre: List[str] = field(default_factory=list)   # technique ids, e.g. ["T1110"]
    evidence: List[str] = field(default_factory=list)
    source_log: str = ""         # which Zeek log it came from
    hosts: List[str] = field(default_factory=list)   # IPs central to this finding (for correlation)

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)

    def to_dict(self) -> dict:
        return asdict(self)


# A detection takes the loaded Zeek logs and returns zero or more findings.
Detection = Callable[[Dict[str, List[dict]]], List[Finding]]

_REGISTRY: List[Detection] = []


def register(fn: Detection) -> Detection:
    """Decorator to register a detection function."""
    _REGISTRY.append(fn)
    return fn


def all_detections() -> List[Detection]:
    return list(_REGISTRY)
