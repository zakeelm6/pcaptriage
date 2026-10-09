"""Desktop application (Tkinter, standard library only).

    pcaptriage gui [capture.pcap]

A native window: pick a capture, press Analyze, read the results in tabs
(findings, attack narrative, flagged servers, files, capture summary). Nothing
runs in a browser and nothing is sent anywhere. The same analysis code as the
command line does the work, on a background thread so the window stays alive.

Everything that does not need a window (ordering, text formatting, engine
detection) lives in plain functions at the top so it can be tested without a
display.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import List, Optional, Tuple

from . import __version__
from .detections.base import Finding
from .mitre import describe
from .pipeline import PCAP_EXTS, Options, Result, analyze_pcap
from .zeek_runner import ZeekError

SEVERITIES = ["critical", "high", "medium", "low", "info"]
# Row backgrounds, light enough for dark text to stay readable.
SEVERITY_BG = {
    "critical": "#f5c2c0", "high": "#f9d3d6", "medium": "#fbe4c2",
    "low": "#d3e6f1", "info": "#e6e8ea",
}
BG = "#f6f7f9"
ACCENT = "#19375f"


# --- logic without a window -------------------------------------------------

def sorted_findings(findings: List[Finding]) -> List[Finding]:
    """Most severe first, then by title, so the list reads top-down by urgency."""
    return sorted(findings, key=lambda f: (-f.severity_rank(), f.title))


def finding_detail(f: Finding) -> str:
    lines = [f"[{f.severity.upper()}] {f.title}", ""]
    if f.mitre:
        lines.append("MITRE ATT&CK: " + ", ".join(f"{t} {describe(t)[0]}" for t in f.mitre))
        lines.append("")
    lines += [f.description, ""]
    if f.evidence:
        lines.append("Evidence")
        lines += [f"  {e}" for e in f.evidence]
    return "\n".join(lines)


def narrative_text(chains: list) -> str:
    if not chains:
        return ("No attack chain.\n\nA chain appears when one host shows up in several phases "
                "of the kill chain (delivery, command and control, propagation...). "
                "That is the strongest sign of a real compromise.")
    out = []
    for c in chains:
        out.append(f"Host {c['host']}:  " + "  >  ".join(c["phases"]))
        for phase in c["phases"]:
            for step in c["steps"][phase]:
                out.append(f"    {phase}: {step}")
        out.append("")
    return "\n".join(out).rstrip()


def headline(result: Result) -> str:
    counts = result.severity_counts()
    parts = [f"{counts[s]} {s}" for s in SEVERITIES if counts.get(s)]
    text = f"{len(result.findings)} finding(s)" + (": " + ", ".join(parts) if parts else "")
    n = len(result.narrative)
    if n:
        text += f"  |  {n} attack chain{'s' if n > 1 else ''}"
    return text


def summary_text(summary: dict) -> str:
    if not summary:
        return ""
    lines = [
        f"Connections:     {summary.get('connections', 0)}",
        f"Distinct hosts:  {summary.get('distinct_hosts', 0)}",
        f"Period:          {summary.get('time_span', '')}",
        f"Zeek logs:       {', '.join(summary.get('log_types', []))}",
        "",
        "Top talkers (connections initiated)",
    ]
    lines += [f"  {host:<18} {n}" for host, n in summary.get("top_talkers", [])]
    lines += ["", "Top services"]
    lines += [f"  {svc:<18} {n}" for svc, n in summary.get("top_services", [])]
    return "\n".join(lines)


def artifact_detail(a: dict) -> str:
    lines = [
        f"{a.get('name', '')}",
        f"Time (UTC):  {a.get('time', '')}",
        f"Type:        {a.get('mime', '')}   {a.get('size', '')} bytes",
        f"Transfer:    {a.get('direction', '')} via {a.get('protocol', '')}",
        f"Between:     {a.get('client', '')}  <->  {a.get('server', '')}",
    ]
    if a.get("url"):
        lines.append(f"Origin:      {a['url']}")
    lines += [f"SHA-256:     {a.get('sha256', '')}", f"Stored as:   {a.get('stored_as', '')}"]
    entries = a.get("entries") or []
    if entries:
        lines += ["", f"Archive contents ({len(entries)}), read from the index only:"]
        lines += [f"  {e['name']}  ({e['size']} bytes{', encrypted' if e.get('encrypted') else ''})"
                  for e in entries]
    return "\n".join(lines)


def detect_engine() -> Tuple[Optional[bool], str]:
    """(use_docker, message). None means neither Zeek nor Docker was found."""
    if shutil.which("zeek"):
        return False, "Zeek found: it will run locally."
    if shutil.which("docker"):
        return True, "Zeek not found, Docker found: Zeek will run in a container."
    return None, "Neither Zeek nor Docker found: install one of them to analyze captures."


def open_folder(path: Path) -> None:
    try:
        if sys.platform.startswith("win"):
            os.startfile(str(path))  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception:  # noqa: BLE001 - best effort, the path is shown in the status bar anyway
        pass


# --- the window -------------------------------------------------------------

class App:
    def __init__(self, root, initial: Optional[str] = None):
        import tkinter as tk
        from tkinter import ttk

        self.tk, self.ttk = tk, ttk
        self.root = root
        self.queue: "queue.Queue[tuple]" = queue.Queue()
        self.workdir = Path(tempfile.mkdtemp(prefix="pcaptriage-gui-"))
        self.result: Optional[Result] = None
        self.artifact_rows: dict = {}

        root.title(f"pcaptriage {__version__}")
        root.geometry("1180x800")
        root.minsize(900, 600)
        root.configure(bg=BG)
        root.protocol("WM_DELETE_WINDOW", self._close)

        self.path = tk.StringVar(value=initial or "")
        use_docker, self.engine_msg = detect_engine()
        self.docker = tk.BooleanVar(value=bool(use_docker))
        self.decode = tk.BooleanVar(value=False)
        self.strict = tk.BooleanVar(value=False)
        self.artifacts = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Choose a capture (.pcap, .pcapng) and press Analyze.")
        self.head = tk.StringVar(value="")

        self._style()
        self._build()
        self._poll()
        if initial and Path(initial).is_file():
            root.after(200, self.start)

    # layout ---------------------------------------------------------------
    def _style(self):
        s = self.ttk.Style(self.root)
        s.theme_use("clam")
        s.configure(".", background=BG)
        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG)
        s.configure("TCheckbutton", background=BG)
        s.configure("Head.TLabel", background=BG, font=("TkDefaultFont", 11, "bold"))
        s.configure("Dim.TLabel", background=BG, foreground="#5a6672")
        s.configure("Accent.TButton", background=ACCENT, foreground="white", padding=(14, 5))
        s.map("Accent.TButton", background=[("active", "#24508a"), ("disabled", "#9aa5b1")])
        s.configure("Treeview", rowheight=24, fieldbackground="white")
        s.configure("Treeview.Heading", font=("TkDefaultFont", 9, "bold"))

    def _build(self):
        tk, ttk = self.tk, self.ttk
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)

        # capture row
        row = ttk.Frame(outer)
        row.pack(fill="x")
        ttk.Label(row, text="Capture").pack(side="left")
        entry = ttk.Entry(row, textvariable=self.path)
        entry.pack(side="left", fill="x", expand=True, padx=8)
        entry.bind("<Return>", lambda _e: self.start())
        ttk.Button(row, text="Browse...", command=self.browse).pack(side="left")
        self.go = ttk.Button(row, text="Analyze", style="Accent.TButton", command=self.start)
        self.go.pack(side="left", padx=(8, 0))

        # options row
        opts = ttk.Frame(outer)
        opts.pack(fill="x", pady=(8, 0))
        ttk.Checkbutton(opts, text="Run Zeek in Docker", variable=self.docker).pack(side="left")
        ttk.Checkbutton(opts, text="Decode Base64/hex/URL", variable=self.decode,
                        command=self._sync_strict).pack(side="left", padx=14)
        self.strict_cb = ttk.Checkbutton(opts, text="Strict (flags, commands, credentials only)",
                                         variable=self.strict, state="disabled")
        self.strict_cb.pack(side="left")
        ttk.Checkbutton(opts, text="Inventory suspicious files", variable=self.artifacts).pack(side="left", padx=14)
        ttk.Label(outer, text=self.engine_msg, style="Dim.TLabel").pack(anchor="w", pady=(2, 0))

        # status
        stat = ttk.Frame(outer)
        stat.pack(fill="x", pady=(8, 0))
        ttk.Label(stat, textvariable=self.head, style="Head.TLabel").pack(side="left")
        self.bar = ttk.Progressbar(outer, mode="indeterminate")

        # tabs
        self.nb = ttk.Notebook(outer)
        self.nb.pack(fill="both", expand=True, pady=(8, 0))
        self.tab_findings = self._split_tab("Findings")
        self.f_tree = self._tree(self.tab_findings[0],
                                 [("sev", "Severity", 80), ("title", "Finding", 520),
                                  ("mitre", "MITRE", 170), ("src", "Source", 100)], height=8)
        self.f_detail = self._text(self.tab_findings[1], height=14)
        self.f_tree.bind("<<TreeviewSelect>>", self._on_finding)
        for sev, bg in SEVERITY_BG.items():
            self.f_tree.tag_configure(sev, background=bg)

        self.n_text = self._text(self._plain_tab("Attack narrative"))

        servers_tab = self._plain_tab("Flagged servers")
        self.s_tree = self._tree(servers_tab,
                                 [("ip", "Address", 120), ("names", "Names", 190),
                                  ("first", "First contact (UTC)", 175), ("sw", "Web server", 230),
                                  ("tls", "TLS issuer", 200), ("by", "Flagged by", 140)])

        self.tab_art = self._split_tab("Files")
        self.a_tree = self._tree(self.tab_art[0],
                                 [("time", "Time (UTC)", 175), ("name", "File", 220),
                                  ("type", "Type", 110), ("size", "Bytes", 70),
                                  ("origin", "Origin", 230), ("sha", "SHA-256", 230)], height=6)
        self.a_detail = self._text(self.tab_art[1], height=12)
        self.a_tree.bind("<<TreeviewSelect>>", self._on_artifact)

        self.c_text = self._text(self._plain_tab("Capture"))

        # actions
        act = ttk.Frame(outer)
        act.pack(fill="x", pady=(8, 0))
        self.btn_html = ttk.Button(act, text="Save HTML report...", command=self.save_html, state="disabled")
        self.btn_json = ttk.Button(act, text="Save findings.json...", command=self.save_json, state="disabled")
        self.btn_copy = ttk.Button(act, text="Copy details", command=self.copy_details, state="disabled")
        self.btn_dir = ttk.Button(act, text="Open output folder", command=self.open_output, state="disabled")
        for b in (self.btn_html, self.btn_json, self.btn_copy, self.btn_dir):
            b.pack(side="left", padx=(0, 8))
        ttk.Label(act, textvariable=self.status, style="Dim.TLabel").pack(side="right")

        self._reset_views()

    def _plain_tab(self, title):
        frame = self.ttk.Frame(self.nb, padding=6)
        self.nb.add(frame, text=title)
        return frame

    def _split_tab(self, title):
        frame = self.ttk.Frame(self.nb, padding=6)
        self.nb.add(frame, text=title)
        pane = self.ttk.PanedWindow(frame, orient="vertical")
        pane.pack(fill="both", expand=True)
        top, bottom = self.ttk.Frame(pane), self.ttk.Frame(pane)
        pane.add(top, weight=2)
        pane.add(bottom, weight=3)
        return top, bottom

    def _tree(self, parent, cols, height=10):
        ttk = self.ttk
        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True)
        tree = ttk.Treeview(wrap, columns=[c[0] for c in cols], show="headings", selectmode="browse", height=height)
        for cid, label, width in cols:
            tree.heading(cid, text=label)
            tree.column(cid, width=width, anchor="w", stretch=True)
        ysb = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        xsb = ttk.Scrollbar(wrap, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)
        ysb.pack(side="right", fill="y")
        xsb.pack(side="bottom", fill="x")
        tree.pack(fill="both", expand=True)
        return tree

    def _text(self, parent, height=10):
        tk, ttk = self.tk, self.ttk
        wrap = ttk.Frame(parent)
        wrap.pack(fill="both", expand=True)
        text = tk.Text(wrap, wrap="word", font="TkFixedFont", relief="flat", padx=8, pady=6,
                       background="white", state="disabled", height=height)
        sb = ttk.Scrollbar(wrap, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        text.pack(fill="both", expand=True)
        return text

    def _set_text(self, widget, content: str):
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        widget.insert("1.0", content)
        widget.configure(state="disabled")

    # actions --------------------------------------------------------------
    def _sync_strict(self):
        self.strict_cb.configure(state="normal" if self.decode.get() else "disabled")
        if not self.decode.get():
            self.strict.set(False)

    def browse(self):
        from tkinter import filedialog

        chosen = filedialog.askopenfilename(
            title="Choose a capture",
            filetypes=[("Packet captures", "*.pcap *.pcapng *.cap"), ("All files", "*.*")],
        )
        if chosen:
            self.path.set(chosen)

    def start(self):
        from tkinter import messagebox

        if str(self.go.cget("state")) == "disabled":
            return
        path = Path(self.path.get().strip()).expanduser()
        if not path.is_file():
            messagebox.showerror("pcaptriage", "That file does not exist.")
            return
        if path.suffix.lower() not in PCAP_EXTS and not messagebox.askyesno(
                "pcaptriage", "This does not look like a capture file. Analyze it anyway?"):
            return

        opts = Options(
            use_docker=self.docker.get(),
            decode=self.decode.get(),
            decode_strict=self.strict.get(),
            artifacts=self.artifacts.get(),
        )
        self._busy(True)
        self.status.set(f"Analyzing {path.name} ...")
        out_root = self.workdir / f"run-{int(time.time())}"

        def work():
            started = time.time()
            try:
                self.queue.put(("done", analyze_pcap(path, out_root, opts), time.time() - started))
            except ZeekError as exc:
                self.queue.put(("error", str(exc)))
            except Exception as exc:  # noqa: BLE001 - never leave the window waiting
                self.queue.put(("error", f"Unexpected error: {exc}"))

        threading.Thread(target=work, daemon=True).start()

    def _busy(self, on: bool):
        self.go.configure(state="disabled" if on else "normal")
        if on:
            self.bar.pack(fill="x", pady=(6, 0), before=self.nb)
            self.bar.start(12)
        else:
            self.bar.stop()
            self.bar.pack_forget()

    def _poll(self):
        try:
            while True:
                msg = self.queue.get_nowait()
                self._busy(False)
                if msg[0] == "done":
                    self.show(msg[1])
                    self.status.set(f"Done in {msg[2]:.1f} s.")
                else:
                    from tkinter import messagebox

                    self.status.set("Analysis failed.")
                    messagebox.showerror("pcaptriage", msg[1])
        except queue.Empty:
            pass
        self.root.after(150, self._poll)

    # results --------------------------------------------------------------
    def _reset_views(self):
        for tree in (self.f_tree, self.s_tree, self.a_tree):
            tree.delete(*tree.get_children())
        for widget in (self.f_detail, self.n_text, self.a_detail, self.c_text):
            self._set_text(widget, "")
        self.head.set("")

    def show(self, result: Result):
        self.result = result
        self._reset_views()
        self.head.set(headline(result))

        self.finding_by_id = {}
        for i, f in enumerate(sorted_findings(result.findings)):
            iid = f"f{i}"
            self.finding_by_id[iid] = f
            self.f_tree.insert("", "end", iid=iid, tags=(f.severity,),
                               values=(f.severity.upper(), f.title, ", ".join(f.mitre), f.source_log))
        kids = self.f_tree.get_children()
        if kids:
            self.f_tree.selection_set(kids[0])
        else:
            self._set_text(self.f_detail, "No findings. Either the capture is clean, or its patterns are "
                                          "outside the current detections.")

        self._set_text(self.n_text, narrative_text(result.narrative))

        for ind in result.indicators or []:
            sw = " / ".join(x for x in (ind.get("server_header"), ind.get("powered_by")) if x)
            self.s_tree.insert("", "end", values=(
                ind["ip"], ", ".join(ind.get("names", [])), ind.get("first_seen", ""), sw,
                ind.get("tls_issuer", ""), ", ".join(ind.get("flagged_by", []))))

        self.artifact_rows = {}
        if result.artifacts:
            for i, a in enumerate(result.artifacts):
                iid = f"a{i}"
                self.artifact_rows[iid] = a
                self.a_tree.insert("", "end", iid=iid, values=(
                    a.get("time", ""), a.get("name", ""), a.get("mime", ""), a.get("size", ""),
                    a.get("url") or a.get("server", ""), a.get("sha256", "")))
            self.a_tree.selection_set(self.a_tree.get_children()[0])
        else:
            self._set_text(self.a_detail,
                           "No files listed. Tick 'Inventory suspicious files' before analyzing to "
                           "carve archives, executables and Office documents out of the capture, "
                           "hash them and list what archives contain (index only, nothing is "
                           "extracted or run).")

        self._set_text(self.c_text, summary_text(result.summary))
        for b in (self.btn_html, self.btn_json, self.btn_copy, self.btn_dir):
            b.configure(state="normal")

    def _on_finding(self, _event=None):
        sel = self.f_tree.selection()
        if sel and sel[0] in self.finding_by_id:
            self._set_text(self.f_detail, finding_detail(self.finding_by_id[sel[0]]))

    def _on_artifact(self, _event=None):
        sel = self.a_tree.selection()
        if sel and sel[0] in self.artifact_rows:
            self._set_text(self.a_detail, artifact_detail(self.artifact_rows[sel[0]]))

    # buttons --------------------------------------------------------------
    def save_html(self):
        self._save(self.result.report_path, "report.html", [("HTML", "*.html")])

    def save_json(self):
        self._save(self.result.json_path, "findings.json", [("JSON", "*.json")])

    def _save(self, source: Path, default: str, types):
        from tkinter import filedialog

        dest = filedialog.asksaveasfilename(initialfile=default, filetypes=types)
        if dest:
            shutil.copyfile(source, dest)
            self.status.set(f"Saved {dest}")

    def copy_details(self):
        widgets = {0: self.f_detail, 1: self.n_text, 3: self.a_detail, 4: self.c_text}
        widget = widgets.get(self.nb.index("current"))
        if widget is None:
            self.status.set("Nothing to copy on this tab (select a cell range in the table instead).")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(widget.get("1.0", "end").strip())
        self.status.set("Copied to the clipboard.")

    def open_output(self):
        if self.result:
            open_folder(self.result.case_dir)
            self.status.set(f"Output folder: {self.result.case_dir}")

    def _close(self):
        shutil.rmtree(self.workdir, ignore_errors=True)
        self.root.destroy()


def launch(initial: Optional[str] = None) -> int:
    import tkinter as tk

    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"[!] cannot open a window: {exc}", file=sys.stderr)
        return 1
    App(root, initial)
    root.mainloop()
    return 0


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else list(argv)
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("[!] Tkinter is not available. On Debian/Ubuntu/Kali: sudo apt install python3-tk",
              file=sys.stderr)
        return 1
    return launch(argv[0] if argv else None)


if __name__ == "__main__":
    raise SystemExit(main())
