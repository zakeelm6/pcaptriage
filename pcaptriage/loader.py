"""Load Zeek JSON logs into memory."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List


def load_logs(logs_dir: str) -> Dict[str, List[dict]]:
    """Read every *.log file in `logs_dir` as JSON lines.

    Returns a mapping: log name without extension -> list of records.
    e.g. {"conn": [...], "dns": [...], "http": [...]}.
    Lines that fail to parse are skipped (Zeek can emit a non-JSON
    header on some logs depending on version/config).
    """
    logs: Dict[str, List[dict]] = {}
    for path in sorted(Path(logs_dir).glob("*.log")):
        name = path.stem
        records: List[dict] = []
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        logs[name] = records
    return logs
