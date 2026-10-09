"""Run Zeek over a pcap and produce JSON logs.

Zeek is the parsing engine. It can run either from a local install or
inside Docker (default on systems where the distro package is broken,
e.g. Kali where the zeek .deb conflicts with a newer libc6).
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path


class ZeekError(RuntimeError):
    pass


def run_zeek(
    pcap_path: str,
    logs_dir: str,
    use_docker: bool = False,
    zeek_cmd: str = "zeek",
    docker_image: str = "zeek/zeek:lts",
    extract: bool = False,
) -> str:
    """Run Zeek on `pcap_path`, writing JSON logs into `logs_dir`.

    Returns the logs directory path. Raises ZeekError on failure.
    """
    pcap = Path(pcap_path).resolve()
    if not pcap.is_file():
        raise ZeekError(f"pcap not found: {pcap}")

    out = Path(logs_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)

    from .artifacts import ARTIFACT_DIR, SCRIPT_NAME, zeek_script

    if extract:
        (out / ARTIFACT_DIR).mkdir(exist_ok=True)
    (out / SCRIPT_NAME).write_text(zeek_script(extract), encoding="utf-8")
    # Relative to the working directory: /work in Docker, `out` locally.
    extra = [SCRIPT_NAME]

    if use_docker:
        # Mount the pcap's directory read-only and the logs dir as the
        # working directory so Zeek writes its *.log files onto the host.
        # On POSIX run as the current user so the logs are not root-owned.
        user = ["--user", f"{os.getuid()}:{os.getgid()}"] if hasattr(os, "getuid") else []
        cmd = [
            "docker", "run", "--rm", *user,
            "-v", f"{pcap.parent}:/pcap:ro",
            "-v", f"{out}:/work",
            "-w", "/work",
            docker_image,
            "zeek", "-C", "-r", f"/pcap/{pcap.name}", "LogAscii::use_json=T", *extra,
        ]
    else:
        if shutil.which(zeek_cmd) is None:
            raise ZeekError(
                f"'{zeek_cmd}' not found on PATH. Install Zeek or use --docker."
            )
        cmd = [zeek_cmd, "-C", "-r", str(pcap), "LogAscii::use_json=T", *extra]

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(out) if not use_docker else None,
            capture_output=True,
            text=True,
            timeout=600,
        )
    except FileNotFoundError as exc:
        raise ZeekError(f"could not launch Zeek ({exc})") from exc
    except subprocess.TimeoutExpired as exc:
        raise ZeekError("Zeek timed out (capture too large?)") from exc

    # Zeek prints parse warnings to stderr but still exits 0; only fail
    # when no log was produced.
    produced = list(out.glob("*.log"))
    if proc.returncode != 0 and not produced:
        raise ZeekError(
            f"Zeek failed (exit {proc.returncode}).\n{proc.stderr.strip()}"
        )
    if not produced:
        raise ZeekError("Zeek produced no logs (empty or unsupported capture).")

    return str(out)
