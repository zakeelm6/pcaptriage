"""Opt-in inventory of the suspicious files that crossed the wire.

With --artifacts, Zeek also carves out archives, executables and Office
documents. For each one we record when and where it came from, its SHA-256
(ready for a reputation lookup, without sending the file anywhere), and, for
archives, the names listed in the archive index.

Listing an archive only reads its index. Nothing is ever extracted from the
archive or executed. The carved files themselves stay on disk in the case
folder: they can be real malware, so treat that folder accordingly.
"""

from __future__ import annotations

import hashlib
import zipfile
from pathlib import Path
from typing import Dict, List

from .detections.base import decode_mime_words, fmt_ts
from .detections.suspicious_download import RISKY

# What gets carved: everything the download detection cares about, plus the
# Office formats that carry macro droppers.
EXTRACT_MIMES = sorted(set(RISKY) | {"application/vnd.ms-excel", "application/msword"})

SCRIPT_NAME = "pcaptriage.zeek"
ARTIFACT_DIR = "artifacts"


def zeek_script(extract: bool = True) -> str:
    """Zeek script loaded on every run.

    Always: log the Server and X-Powered-By response headers (Zeek does not
    keep them), into pcaptriage_http.log, so the report can name the web server
    software behind a suspicious address.
    With extract=True: also carve the wanted MIME types, one file per fuid.
    """
    script = """module PcapTriage;

export {
    redef enum Log::ID += { HEADERS };
    type Info: record {
        ts: time &log;
        uid: string &log;
        resp_h: addr &log;
        name: string &log;
        value: string &log;
    };
}

event zeek_init() &priority=5
    {
    Log::create_stream(PcapTriage::HEADERS, [$columns=Info, $path="pcaptriage_http"]);
    }

event http_header(c: connection, is_orig: bool, name: string, value: string)
    {
    if ( ! is_orig && ( name == "SERVER" || name == "X-POWERED-BY" ) )
        Log::write(PcapTriage::HEADERS, [$ts=network_time(), $uid=c$uid,
                   $resp_h=c$id$resp_h, $name=name, $value=value]);
    }
"""
    if extract:
        mimes = ", ".join(f'"{m}"' for m in EXTRACT_MIMES)
        script += f"""
@load base/frameworks/files
@load base/files/extract

redef FileExtract::prefix = "{ARTIFACT_DIR}/";

const pcaptriage_mimes: set[string] = {{ {mimes} }};

event file_sniff(f: fa_file, meta: fa_metadata)
    {{
    if ( meta?$mime_type && meta$mime_type in pcaptriage_mimes )
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT, [$extract_filename=f$id]);
    }}
"""
    return script


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def archive_entries(path: Path) -> List[dict]:
    """Names (and sizes) listed in a ZIP index, or [] if it is not a readable ZIP."""
    if not zipfile.is_zipfile(path):
        return []
    try:
        with zipfile.ZipFile(path) as z:  # reads the central directory only
            return [
                {"name": i.filename, "size": i.file_size, "encrypted": bool(i.flag_bits & 1)}
                for i in z.infolist()
            ]
    except (zipfile.BadZipFile, OSError, NotImplementedError):
        return []


def collect_artifacts(logs: Dict[str, List[dict]], case_dir: Path) -> List[dict]:
    """Describe every carved file, joined with what Zeek logged about it."""
    art_dir = Path(case_dir) / "zeek-logs" / ARTIFACT_DIR
    if not art_dir.is_dir():
        return []

    http_by_uid = {r["uid"]: r for r in logs.get("http", []) if r.get("uid")}
    out: List[dict] = []
    for rec in logs.get("files", []):
        fuid = rec.get("fuid")
        path = art_dir / fuid if fuid else None
        if not path or not path.is_file():
            continue
        http = http_by_uid.get(rec.get("uid"), {})
        uri = http.get("uri", "")
        name = decode_mime_words(
            rec.get("filename") or (uri.rsplit("/", 1)[-1] if uri else "") or fuid
        )
        out.append(
            {
                "time": fmt_ts(rec["ts"]) if rec.get("ts") is not None else "",
                "name": name,
                "mime": rec.get("mime_type", ""),
                "size": path.stat().st_size,
                "sha256": _sha256(path),
                "protocol": rec.get("source", ""),
                "client": rec.get("id.orig_h", ""),
                "server": rec.get("id.resp_h", ""),
                "domain": http.get("host", ""),
                "url": (http.get("host", "") + uri) if http else "",
                "direction": "sent" if rec.get("is_orig") else "received",
                "entries": archive_entries(path),
                "stored_as": str(path.relative_to(Path(case_dir))),
            }
        )
    out.sort(key=lambda a: a["time"])
    return out
