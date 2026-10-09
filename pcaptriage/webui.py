"""Local web UI: drop a pcap in the browser, get the report.

    pcaptriage serve

Standard library only. Binds to 127.0.0.1 by default: there is no
authentication, so do not expose it to a network you do not trust.
"""

from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import signal
import sys
import tempfile
import threading
import webbrowser
from dataclasses import replace
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .pipeline import PCAP_EXTS, Options, analyze_pcap
from .zeek_runner import ZeekError

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
JOB_FILE_RE = re.compile(r"^/jobs/([0-9a-f]{16})/(report\.html|findings\.json)$")

# CSP for the generated report: static HTML + inline CSS, no scripts at all.
REPORT_CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src data:; "
    "base-uri 'none'; form-action 'none'"
)
UI_CSP = (
    "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; "
    "connect-src 'self'; base-uri 'none'; form-action 'none'"
)


def safe_name(raw: str):
    """Reduce an uploaded filename to a safe basename, or None if not a pcap."""
    base = os.path.basename((raw or "").replace("\\", "/"))
    base = re.sub(r"[^A-Za-z0-9._-]", "_", base).lstrip(".")
    if Path(base).suffix.lower() not in PCAP_EXTS:
        return None
    return base[:100]


def _host_header_name(value: str) -> str:
    value = (value or "").strip().lower()
    if value.startswith("["):                       # [::1]:8080
        return value[1:value.find("]")] if "]" in value else value
    return value.split(":")[0]


class App:
    def __init__(self, workdir: Path, opts: Options, max_bytes: int, loopback_only: bool):
        self.workdir = workdir
        self.opts = opts
        self.max_bytes = max_bytes
        self.loopback_only = loopback_only
        self.jobs: dict = {}
        self.lock = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    server_version = f"pcaptriage/{__version__}"

    @property
    def app(self) -> App:
        return self.server.app  # type: ignore[attr-defined]

    def log_message(self, fmt, *args):  # quieter than the default
        sys.stderr.write("[web] " + (fmt % args) + "\n")

    # --- helpers ---------------------------------------------------------
    def _send(self, code: int, body: bytes, ctype: str, csp: str = UI_CSP, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", csp)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json; charset=utf-8")

    def _host_ok(self) -> bool:
        if not self.app.loopback_only:
            return True
        return _host_header_name(self.headers.get("Host", "")) in LOOPBACK_HOSTS

    # --- GET -------------------------------------------------------------
    def do_GET(self):
        if not self._host_ok():
            return self._json(403, {"error": "bad Host header"})
        path = urlparse(self.path).path

        if path == "/":
            page = INDEX_HTML.replace("__MAX_MB__", str(self.app.max_bytes // (1024 * 1024)))
            page = page.replace("__VERSION__", __version__)
            return self._send(200, page.encode(), "text/html; charset=utf-8")

        if path == "/api/jobs":
            with self.app.lock:
                jobs = sorted(self.app.jobs.values(), key=lambda j: j["at"], reverse=True)
            return self._json(200, [
                {k: j[k] for k in ("id", "name", "total", "severity", "chains", "at")}
                for j in jobs
            ])

        m = JOB_FILE_RE.match(path)
        if m:
            with self.app.lock:
                job = self.app.jobs.get(m.group(1))
            if not job:
                return self._json(404, {"error": "unknown job"})
            fpath = job["case_dir"] / m.group(2)
            if not fpath.is_file():
                return self._json(404, {"error": "file missing"})
            if m.group(2) == "report.html":
                return self._send(200, fpath.read_bytes(), "text/html; charset=utf-8", REPORT_CSP)
            return self._send(200, fpath.read_bytes(), "application/json; charset=utf-8", REPORT_CSP)

        self._json(404, {"error": "not found"})

    # --- POST ------------------------------------------------------------
    def do_POST(self):
        if not self._host_ok():
            return self._json(403, {"error": "bad Host header"})
        parsed = urlparse(self.path)
        if parsed.path != "/api/analyze":
            return self._json(404, {"error": "not found"})
        # A custom header cannot be sent cross-origin without a CORS preflight,
        # which this server never grants: it blocks drive-by posts from other sites.
        if self.headers.get("X-Requested-With") != "pcaptriage":
            return self._json(403, {"error": "missing X-Requested-With header"})

        q = parse_qs(parsed.query)
        name = safe_name(q.get("name", [""])[0])
        if not name:
            return self._json(400, {"error": "file must be a .pcap, .pcapng or .cap"})

        raw_len = self.headers.get("Content-Length")
        if raw_len is None or not raw_len.isdigit():
            return self._json(411, {"error": "Content-Length required"})
        length = int(raw_len)
        if length <= 0:
            return self._json(400, {"error": "empty upload"})
        if length > self.app.max_bytes:
            return self._json(413, {"error": f"file too large (max {self.app.max_bytes // (1024 * 1024)} MB)"})

        job_id = secrets.token_hex(8)
        job_dir = self.app.workdir / job_id
        in_dir = job_dir / "in"
        in_dir.mkdir(parents=True)
        pcap_path = in_dir / name

        remaining = length
        with pcap_path.open("wb") as fh:
            while remaining:
                chunk = self.rfile.read(min(1 << 20, remaining))
                if not chunk:
                    break
                fh.write(chunk)
                remaining -= len(chunk)
        if remaining:
            shutil.rmtree(job_dir, ignore_errors=True)
            return self._json(400, {"error": "upload interrupted"})

        opts = replace(
            self.app.opts,
            decode=q.get("decode", ["0"])[0] == "1",
            decode_strict=q.get("strict", ["0"])[0] == "1",
            decode_schemes=q.get("schemes", [""])[0][:200],
        )
        try:
            res = analyze_pcap(pcap_path, job_dir / "out", opts)
        except ZeekError as exc:
            shutil.rmtree(job_dir, ignore_errors=True)
            return self._json(422, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001 - never leave the client hanging
            shutil.rmtree(job_dir, ignore_errors=True)
            return self._json(500, {"error": f"analysis failed: {exc}"})
        finally:
            shutil.rmtree(in_dir, ignore_errors=True)  # the capture itself is not kept

        job = {
            "id": job_id,
            "name": res.pcap_name,
            "total": len(res.findings),
            "severity": res.severity_counts(),
            "chains": len(res.narrative),
            "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "case_dir": res.case_dir,
        }
        with self.app.lock:
            self.app.jobs[job_id] = job
        self._json(200, {k: job[k] for k in ("id", "name", "total", "severity", "chains", "at")})


def serve(host: str, port: int, opts: Options, workdir=None,
          max_mb: int = 1000, open_browser: bool = True) -> int:
    own_tmp = workdir is None
    work = Path(tempfile.mkdtemp(prefix="pcaptriage-")) if own_tmp else Path(workdir)
    work.mkdir(parents=True, exist_ok=True)

    loopback = host in LOOPBACK_HOSTS
    app = App(work, opts, max_mb * 1024 * 1024, loopback)
    try:
        httpd = ThreadingHTTPServer((host, port), Handler)
    except OSError as exc:
        print(f"[!] cannot listen on {host}:{port}: {exc}", file=sys.stderr)
        return 1
    httpd.app = app  # type: ignore[attr-defined]
    httpd.daemon_threads = True

    shown = "127.0.0.1" if host in ("0.0.0.0", "") else host
    url = f"http://{shown}:{port}/"
    print(f"[*] pcaptriage {__version__} web UI on {url}  (Ctrl+C to stop)")
    print(f"[*] working directory: {work}")
    if not loopback:
        print("[!] listening beyond localhost with NO authentication: anyone who can "
              "reach this port can upload captures and read reports.", file=sys.stderr)
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:  # noqa: BLE001
            pass
    def _stop(signum, frame):  # SIGTERM (docker stop, kill) cleans up like Ctrl+C
        raise KeyboardInterrupt

    try:
        signal.signal(signal.SIGTERM, _stop)
    except (ValueError, OSError):  # not in the main thread / unsupported platform
        pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopping")
    finally:
        httpd.server_close()
        if own_tmp:
            shutil.rmtree(work, ignore_errors=True)
    return 0


INDEX_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcaptriage</title>
<style>
  :root { --bg:#f6f7f9; --card:#fff; --fg:#1b1f24; --muted:#5a6672; --line:#e2e6ea;
          --accent:#19375f; --accent-fg:#fff; --ok:#1a7f4b; --bad:#b4232a; }
  @media (prefers-color-scheme: dark) {
    :root { --bg:#14171c; --card:#1d222a; --fg:#e8ecf1; --muted:#9aa5b1; --line:#2b323c;
            --accent:#7fa8d8; --accent-fg:#0d1117; --ok:#4cc38a; --bad:#ff7b72; }
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg);
         font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }
  .wrap { max-width:760px; margin:0 auto; padding:24px 16px 64px; }
  h1 { font-size:22px; margin:0; }
  .sub { color:var(--muted); font-size:13px; margin:2px 0 22px; }
  #drop { border:2px dashed var(--line); border-radius:12px; background:var(--card);
          padding:34px 16px; text-align:center; cursor:pointer; }
  #drop.over { border-color:var(--accent); }
  #drop strong { display:block; font-size:16px; }
  #drop span { color:var(--muted); font-size:13px; }
  .opts { display:flex; flex-wrap:wrap; gap:14px; align-items:center; margin:14px 2px; font-size:14px; }
  .opts label { display:flex; gap:6px; align-items:center; }
  .opts input[type=text] { width:230px; padding:4px 8px; border:1px solid var(--line);
         border-radius:6px; background:var(--card); color:var(--fg); }
  #status { min-height:24px; margin:10px 2px; font-size:14px; }
  #status.err { color:var(--bad); }
  .bar { height:6px; background:var(--line); border-radius:3px; overflow:hidden; margin-top:6px; }
  .bar > i { display:block; height:100%; width:0; background:var(--accent); }
  h2 { font-size:16px; margin:26px 0 8px; }
  .job { background:var(--card); border:1px solid var(--line); border-radius:10px;
         padding:12px 14px; margin:10px 0; }
  .job .top { display:flex; justify-content:space-between; gap:10px; flex-wrap:wrap; }
  .job .name { font-weight:600; word-break:break-all; }
  .job .meta { color:var(--muted); font-size:12px; }
  .chips { display:flex; gap:6px; flex-wrap:wrap; margin:8px 0; }
  .chip { font-size:12px; font-weight:700; padding:1px 8px; border-radius:4px; color:#fff; }
  .critical{background:#b4232a} .high{background:#d1495b} .medium{background:#e08a1e}
  .low{background:#3a7ca5} .info{background:#6c757d} .clean{background:var(--ok)}
  .chain { background:#b4232a; }
  .links a { margin-right:14px; color:var(--accent); font-size:14px; }
  .empty { color:var(--muted); font-size:14px; }
</style>
</head>
<body>
<div class="wrap">
  <h1>pcaptriage</h1>
  <p class="sub">Drop a capture, get a triage report. Runs on this machine, nothing leaves it. v__VERSION__</p>

  <div id="drop" tabindex="0">
    <strong>Drop a .pcap / .pcapng here, or click to choose</strong>
    <span>max __MAX_MB__ MB</span>
    <input id="file" type="file" accept=".pcap,.pcapng,.cap" hidden>
  </div>

  <div class="opts">
    <label><input id="decode" type="checkbox"> decode Base64/hex/URL...</label>
    <label><input id="strict" type="checkbox"> strict (flags, commands, creds only)</label>
    <label>schemes <input id="schemes" type="text" placeholder="default, or: base64,hex,all"></label>
  </div>

  <div id="status"></div>
  <div class="bar" id="barwrap" hidden><i id="bar"></i></div>

  <h2>This session</h2>
  <div id="jobs"><p class="empty">Nothing analyzed yet.</p></div>
</div>

<script>
const $ = s => document.querySelector(s);
const MAX = __MAX_MB__ * 1024 * 1024;
const drop = $("#drop"), fileInput = $("#file");

function setStatus(text, err) { const s = $("#status"); s.textContent = text; s.className = err ? "err" : ""; }
function setBar(p) { const w = $("#barwrap"); w.hidden = p === null; if (p !== null) $("#bar").style.width = p + "%"; }

function jobCard(j) {
  const d = document.createElement("div"); d.className = "job";
  const top = document.createElement("div"); top.className = "top";
  const n = document.createElement("span"); n.className = "name"; n.textContent = j.name;
  const m = document.createElement("span"); m.className = "meta"; m.textContent = j.at.replace("T", " ").replace("+00:00", " UTC");
  top.append(n, m);
  const chips = document.createElement("div"); chips.className = "chips";
  const order = ["critical", "high", "medium", "low", "info"];
  let any = false;
  for (const s of order) if (j.severity[s]) {
    any = true;
    const c = document.createElement("span"); c.className = "chip " + s; c.textContent = j.severity[s] + " " + s; chips.append(c);
  }
  if (!any) { const c = document.createElement("span"); c.className = "chip clean"; c.textContent = "no findings"; chips.append(c); }
  if (j.chains) { const c = document.createElement("span"); c.className = "chip chain"; c.textContent = j.chains + " attack chain" + (j.chains > 1 ? "s" : ""); chips.append(c); }
  const links = document.createElement("div"); links.className = "links";
  const a = document.createElement("a"); a.href = "/jobs/" + j.id + "/report.html"; a.target = "_blank"; a.rel = "noopener"; a.textContent = "Open report";
  const b = document.createElement("a"); b.href = "/jobs/" + j.id + "/findings.json"; b.target = "_blank"; b.rel = "noopener"; b.textContent = "findings.json";
  links.append(a, b);
  d.append(top, chips, links);
  return d;
}

function addJob(j) {
  const box = $("#jobs"); if (box.querySelector(".empty")) box.textContent = "";
  box.prepend(jobCard(j));
}

fetch("/api/jobs").then(r => r.json()).then(js => js.slice().reverse().forEach(addJob)).catch(() => {});

function analyze(file) {
  if (!/\.(pcap|pcapng|cap)$/i.test(file.name)) return setStatus("Not a capture file (.pcap, .pcapng, .cap).", true);
  if (file.size > MAX) return setStatus("File too large (max __MAX_MB__ MB).", true);
  const p = new URLSearchParams({ name: file.name });
  if ($("#decode").checked) p.set("decode", "1");
  if ($("#strict").checked) { p.set("decode", "1"); p.set("strict", "1"); }
  if ($("#schemes").value.trim()) p.set("schemes", $("#schemes").value.trim());

  const xhr = new XMLHttpRequest();
  xhr.open("POST", "/api/analyze?" + p.toString());
  xhr.setRequestHeader("X-Requested-With", "pcaptriage");
  xhr.upload.onprogress = e => { if (e.lengthComputable) { const pc = Math.round(100 * e.loaded / e.total); setBar(pc); setStatus("Uploading " + file.name + " ... " + pc + "%"); } };
  xhr.upload.onload = () => { setBar(null); setStatus("Analyzing " + file.name + " with Zeek ..."); };
  xhr.onload = () => {
    setBar(null);
    let body = {}; try { body = JSON.parse(xhr.responseText); } catch (e) {}
    if (xhr.status === 200) { setStatus("Done: " + body.total + " finding(s)."); addJob(body); }
    else setStatus(body.error || ("Failed (HTTP " + xhr.status + ")."), true);
  };
  xhr.onerror = () => { setBar(null); setStatus("Network error (server stopped, or upload rejected).", true); };
  setStatus("Uploading " + file.name + " ..."); setBar(0);
  xhr.send(file);
}

drop.onclick = () => fileInput.click();
drop.onkeydown = e => { if (e.key === "Enter" || e.key === " ") fileInput.click(); };
fileInput.onchange = () => { if (fileInput.files[0]) analyze(fileInput.files[0]); fileInput.value = ""; };
["dragenter", "dragover"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.add("over"); }));
["dragleave", "drop"].forEach(ev => drop.addEventListener(ev, e => { e.preventDefault(); drop.classList.remove("over"); }));
drop.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) analyze(f); });
</script>
</body>
</html>
"""
