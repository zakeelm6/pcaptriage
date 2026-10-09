"""Command-line interface for pcaptriage."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List

from . import __version__
from .pipeline import PCAP_EXTS, Options, analyze_pcap
from .zeek_runner import ZeekError


def _options(args) -> Options:
    return Options(
        use_docker=args.docker,
        zeek_cmd=args.zeek_cmd,
        docker_image=args.docker_image,
        decode=args.decode,
        decode_schemes=args.decode_schemes,
        decode_strict=args.decode_strict,
        artifacts=args.artifacts,
    )


def _analyze_one(pcap: Path, out_root: Path, args) -> int:
    """Analyze a single pcap. Returns the number of findings, or -1 on failure."""
    print(f"[*] {pcap.name}: running Zeek ({'docker' if args.docker else 'local'})...")
    try:
        res = analyze_pcap(pcap, out_root, _options(args))
    except ZeekError as exc:
        print(f"[!] {pcap.name}: {exc}", file=sys.stderr)
        return -1

    sev_str = ", ".join(f"{v} {k}" for k, v in sorted(res.severity_counts().items())) or "none"
    print(f"[+] {pcap.name}: {len(res.findings)} finding(s) ({sev_str}) -> {res.report_path}")
    return len(res.findings)


def _collect_pcaps(target: Path) -> List[Path]:
    if target.is_file():
        return [target]
    if target.is_dir():
        return sorted(p for p in target.rglob("*") if p.suffix.lower() in PCAP_EXTS)
    return []


def _serve_main(argv) -> int:
    from .webui import serve

    p = argparse.ArgumentParser(
        prog="pcaptriage serve",
        description="Local web UI: drop a pcap in the browser, get the report.",
    )
    p.add_argument("--host", default="127.0.0.1",
                   help="address to listen on (default 127.0.0.1, localhost only; "
                        "use 0.0.0.0 inside a container, there is NO authentication)")
    p.add_argument("--port", type=int, default=8080, help="port (default 8080)")
    p.add_argument("--docker", action="store_true",
                   help="run Zeek via Docker instead of a local install")
    p.add_argument("--zeek-cmd", default="zeek", help="local Zeek binary (default: zeek)")
    p.add_argument("--docker-image", default="zeek/zeek:lts",
                   help="Zeek Docker image (default: zeek/zeek:lts)")
    p.add_argument("--workdir", default=None,
                   help="keep results here (default: a temp dir deleted on exit)")
    p.add_argument("--max-size-mb", type=int, default=1000,
                   help="maximum upload size in MB (default 1000)")
    p.add_argument("--no-browser", action="store_true", help="do not open the browser")
    a = p.parse_args(argv)
    opts = Options(use_docker=a.docker, zeek_cmd=a.zeek_cmd, docker_image=a.docker_image)
    return serve(a.host, a.port, opts, workdir=a.workdir,
                 max_mb=a.max_size_mb, open_browser=not a.no_browser)


def main(argv=None) -> int:
    raw = sys.argv[1:] if argv is None else list(argv)
    if raw and raw[0] == "serve":
        return _serve_main(raw[1:])
    if raw and raw[0] == "gui":
        from .gui import main as gui_main

        return gui_main(raw[1:])

    parser = argparse.ArgumentParser(
        prog="pcaptriage",
        description="Automated pcap triage on top of Zeek, mapped to MITRE ATT&CK.",
        epilog="Desktop app: 'pcaptriage gui'. Browser UI: 'pcaptriage serve'.",
    )
    parser.add_argument("target", help="a .pcap file or a directory of captures")
    parser.add_argument(
        "-o", "--output", default="pcaptriage-report",
        help="output directory (default: ./pcaptriage-report)",
    )
    parser.add_argument(
        "--docker", action="store_true",
        help="run Zeek via Docker instead of a local install",
    )
    parser.add_argument(
        "--decode", action="store_true",
        help="decode encoded content in HTTP/DNS/FTP fields "
             "(noisy; useful for CTF and lab captures)",
    )
    parser.add_argument(
        "--decode-schemes", default="", metavar="LIST",
        help="comma-separated decoders to use with --decode: "
             "base64,base32,hex,url,rot13,gzip (default). Add base85 or pass "
             "'all' to include it (base85 is noisy inside URIs).",
    )
    parser.add_argument(
        "--decode-strict", action="store_true",
        help="noise elimination: with --decode, keep only decodings that "
             "contain flags, commands or credentials (drops meaningful-looking "
             "but unremarkable text)",
    )
    parser.add_argument(
        "--artifacts", action="store_true",
        help="carve archives/executables/Office files out of the capture, "
             "hash them (SHA-256) and list archive contents (index only, nothing "
             "is extracted or run). The carved files are kept in the case folder "
             "and may be real malware.",
    )
    parser.add_argument(
        "--zeek-cmd", default="zeek",
        help="local Zeek binary name/path (default: zeek)",
    )
    parser.add_argument(
        "--docker-image", default="zeek/zeek:lts",
        help="Zeek Docker image (default: zeek/zeek:lts)",
    )
    parser.add_argument("--version", action="version", version=f"pcaptriage {__version__}")
    args = parser.parse_args(raw)

    target = Path(args.target)
    pcaps = _collect_pcaps(target)
    if not pcaps:
        print(f"[!] no pcap found at: {target}", file=sys.stderr)
        return 2

    out_root = Path(args.output)
    out_root.mkdir(parents=True, exist_ok=True)

    total = 0
    failures = 0
    for pcap in pcaps:
        n = _analyze_one(pcap, out_root, args)
        if n < 0:
            failures += 1
        else:
            total += n

    print(f"\n[=] done: {len(pcaps) - failures}/{len(pcaps)} capture(s) analyzed, "
          f"{total} finding(s) total. Reports in {out_root}/")
    return 1 if failures and failures == len(pcaps) else 0


if __name__ == "__main__":
    raise SystemExit(main())
