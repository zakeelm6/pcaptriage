"""Minimal MITRE ATT&CK technique lookup used by detections."""

from __future__ import annotations

from typing import Dict, Tuple

# technique id -> (name, url)
TECHNIQUES: Dict[str, Tuple[str, str]] = {
    "T1046": ("Network Service Discovery", "https://attack.mitre.org/techniques/T1046/"),
    "T1040": ("Network Sniffing", "https://attack.mitre.org/techniques/T1040/"),
    "T1110": ("Brute Force", "https://attack.mitre.org/techniques/T1110/"),
    "T1552": ("Unsecured Credentials", "https://attack.mitre.org/techniques/T1552/"),
    "T1071": ("Application Layer Protocol", "https://attack.mitre.org/techniques/T1071/"),
    "T1071.004": ("Application Layer Protocol: DNS", "https://attack.mitre.org/techniques/T1071/004/"),
    "T1095": ("Non-Application Layer Protocol", "https://attack.mitre.org/techniques/T1095/"),
    "T1573": ("Encrypted Channel", "https://attack.mitre.org/techniques/T1573/"),
    "T1048": ("Exfiltration Over Alternative Protocol", "https://attack.mitre.org/techniques/T1048/"),
    "T1557.001": ("Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "https://attack.mitre.org/techniques/T1557/001/"),
    "T1557": ("Adversary-in-the-Middle", "https://attack.mitre.org/techniques/T1557/"),
}


def describe(technique_id: str) -> Tuple[str, str]:
    """Return (name, url) for a technique id, with a safe fallback."""
    return TECHNIQUES.get(
        technique_id,
        (technique_id, f"https://attack.mitre.org/techniques/{technique_id.replace('.', '/')}/"),
    )
