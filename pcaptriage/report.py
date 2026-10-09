"""Build the summary and render the HTML report."""

from __future__ import annotations

import html
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List

from .detections.base import Finding, SEVERITY_ORDER
from .mitre import describe

SEVERITY_COLORS = {
    "critical": "#b4232a",
    "high": "#d1495b",
    "medium": "#e08a1e",
    "low": "#3a7ca5",
    "info": "#6c757d",
}


def build_summary(logs: Dict[str, List[dict]]) -> dict:
    """Compute high-level stats from conn.log."""
    conns = logs.get("conn", [])
    talkers: Counter = Counter()
    services: Counter = Counter()
    hosts = set()
    ts_values = []

    for rec in conns:
        src = rec.get("id.orig_h")
        dst = rec.get("id.resp_h")
        if src:
            talkers[src] += 1
            hosts.add(src)
        if dst:
            hosts.add(dst)
        svc = rec.get("service") or f"port/{rec.get('id.resp_p')}"
        services[svc] += 1
        ts = rec.get("ts")
        if isinstance(ts, (int, float)):
            ts_values.append(ts)

    span = ""
    if ts_values:
        start = datetime.fromtimestamp(min(ts_values), tz=timezone.utc)
        end = datetime.fromtimestamp(max(ts_values), tz=timezone.utc)
        span = f"{start.isoformat()} to {end.isoformat()}"

    return {
        "connections": len(conns),
        "distinct_hosts": len(hosts),
        "log_types": sorted(logs.keys()),
        "top_talkers": talkers.most_common(10),
        "top_services": services.most_common(10),
        "time_span": span,
    }


def _esc(x) -> str:
    return html.escape(str(x))


def _finding_card(f: Finding) -> str:
    color = SEVERITY_COLORS.get(f.severity, "#6c757d")
    mitre_html = " ".join(
        f'<a class="mitre" href="{_esc(describe(t)[1])}" target="_blank" rel="noopener">'
        f"{_esc(t)} {_esc(describe(t)[0])}</a>"
        for t in f.mitre
    )
    evidence_html = ""
    if f.evidence:
        items = "".join(f"<li><code>{_esc(e)}</code></li>" for e in f.evidence)
        evidence_html = f"<details><summary>Evidence ({len(f.evidence)})</summary><ul>{items}</ul></details>"
    return f"""
    <article class="finding" style="--sev:{color}">
      <header>
        <span class="badge" style="background:{color}">{_esc(f.severity.upper())}</span>
        <h3>{_esc(f.title)}</h3>
      </header>
      <p>{_esc(f.description)}</p>
      <div class="mitre-row">{mitre_html}</div>
      {evidence_html}
      <footer>source: {_esc(f.source_log)}</footer>
    </article>
    """


def _narrative_html(chains: list) -> str:
    if not chains:
        return ""
    cards = []
    for c in chains:
        flow = ' <span class="arrow">&rarr;</span> '.join(_esc(p) for p in c["phases"])
        steps = "".join(
            f"<li><strong>{_esc(p)}:</strong> {_esc('; '.join(c['steps'][p]))}</li>"
            for p in c["phases"]
        )
        cards.append(
            f"""
            <article class="chain">
              <header><span class="pivot">{_esc(c['host'])}</span>
                <span class="flow">{flow}</span></header>
              <ul>{steps}</ul>
            </article>"""
        )
    return f"""
    <section>
      <h2>Attack narrative</h2>
      <p class="sub">Hosts that appear across several phases of the kill chain.
        A single host spanning multiple phases is the strongest sign of a real
        compromise, not isolated noise.</p>
      {''.join(cards)}
    </section>"""


def _artifacts_html(artifacts: list) -> str:
    if not artifacts:
        return ""
    rows = []
    for a in artifacts:
        entries = ""
        if a.get("entries"):
            items = "".join(
                f"<li><code>{_esc(e['name'])}</code> ({_esc(e['size'])} bytes"
                f"{', encrypted' if e.get('encrypted') else ''})</li>"
                for e in a["entries"][:20]
            )
            entries = f"<details><summary>Archive contents ({len(a['entries'])})</summary><ul>{items}</ul></details>"
        origin = a.get("url") or a.get("server") or ""
        rows.append(
            f"""<tr>
              <td>{_esc(a.get('time', ''))}</td>
              <td><code>{_esc(a['name'])}</code>{entries}</td>
              <td>{_esc(a.get('mime', ''))}<br>{_esc(a.get('size', ''))} bytes</td>
              <td>{_esc(a.get('direction', ''))} via {_esc(a.get('protocol', ''))}<br>
                  <code>{_esc(a.get('client', ''))}</code> &harr; <code>{_esc(a.get('server', ''))}</code>
                  {('<br>' + _esc(origin)) if origin else ''}</td>
              <td><code>{_esc(a.get('sha256', ''))}</code></td>
            </tr>"""
        )
    return f"""
    <section>
      <h2>Artifacts</h2>
      <p class="sub">Files carved from the capture. Hashes are ready for a reputation
        lookup; nothing was uploaded. Archive contents come from the archive index only:
        nothing was extracted or run. The carved files are on disk in the case folder
        and may be real malware.</p>
      <div class="scroll"><table class="art">
        <tr><th>Time (UTC)</th><th>File</th><th>Type</th><th>Transfer</th><th>SHA-256</th></tr>
        {''.join(rows)}
      </table></div>
    </section>"""


def render_html(pcap_name: str, summary: dict, findings: List[Finding],
                narrative: list = None, artifacts: list = None) -> str:
    narrative = narrative or []
    findings = sorted(findings, key=lambda f: f.severity_rank(), reverse=True)
    counts = Counter(f.severity for f in findings)

    sev_tiles = "".join(
        f'<div class="tile" style="border-color:{SEVERITY_COLORS[s]}">'
        f'<span class="n">{counts.get(s, 0)}</span><span class="l">{s}</span></div>'
        for s in ("critical", "high", "medium", "low", "info")
    )

    talkers_rows = "".join(
        f"<tr><td><code>{_esc(h)}</code></td><td>{n}</td></tr>" for h, n in summary["top_talkers"]
    )
    services_rows = "".join(
        f"<tr><td>{_esc(s)}</td><td>{n}</td></tr>" for s, n in summary["top_services"]
    )
    findings_html = "".join(_finding_card(f) for f in findings) or (
        '<p class="empty">No findings. Either the capture is clean, or the '
        "patterns are outside the current detection set.</p>"
    )

    generated = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pcaptriage report</title>
<style>
  :root {{
    --bg:#f6f7f9; --card:#ffffff; --fg:#1b1f24; --muted:#5a6672;
    --line:#e2e6ea; --accent:#19375f;
  }}
  @media (prefers-color-scheme: dark) {{
    :root {{
      --bg:#14171c; --card:#1d222a; --fg:#e8ecf1; --muted:#9aa5b1;
      --line:#2b323c; --accent:#7fa8d8;
    }}
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg);
    font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:24px 16px 64px; }}
  h1 {{ font-size:22px; margin:0 0 4px; }}
  .sub {{ color:var(--muted); font-size:13px; margin-bottom:20px; }}
  .tiles {{ display:flex; gap:10px; flex-wrap:wrap; margin:16px 0 28px; }}
  .tile {{ background:var(--card); border:1px solid var(--line);
    border-left-width:5px; border-radius:8px; padding:10px 16px; min-width:92px; }}
  .tile .n {{ display:block; font-size:24px; font-weight:700; }}
  .tile .l {{ display:block; font-size:11px; text-transform:uppercase;
    letter-spacing:.06em; color:var(--muted); }}
  section {{ margin:28px 0; }}
  .grid {{ display:grid; grid-template-columns:1fr 1fr; gap:20px; }}
  @media (max-width:640px) {{ .grid {{ grid-template-columns:1fr; }} }}
  table {{ width:100%; border-collapse:collapse; background:var(--card);
    border:1px solid var(--line); border-radius:8px; overflow:hidden; }}
  th,td {{ text-align:left; padding:7px 12px; border-bottom:1px solid var(--line); font-size:13px; }}
  th {{ color:var(--muted); font-weight:600; }}
  tr:last-child td {{ border-bottom:none; }}
  .finding {{ background:var(--card); border:1px solid var(--line);
    border-left:5px solid var(--sev); border-radius:8px; padding:14px 16px; margin:14px 0; }}
  .finding header {{ display:flex; align-items:center; gap:10px; }}
  .finding h3 {{ margin:0; font-size:16px; }}
  .badge {{ color:#fff; font-size:11px; font-weight:700; padding:2px 8px;
    border-radius:4px; letter-spacing:.04em; }}
  .mitre-row {{ margin:8px 0; display:flex; gap:8px; flex-wrap:wrap; }}
  a.mitre {{ font-size:12px; text-decoration:none; color:var(--accent);
    border:1px solid var(--accent); border-radius:4px; padding:1px 7px; }}
  details {{ margin-top:8px; }}
  summary {{ cursor:pointer; color:var(--muted); font-size:13px; }}
  ul {{ margin:8px 0; padding-left:18px; }}
  code {{ font:12px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;
    background:rgba(127,127,127,.12); padding:1px 5px; border-radius:4px; word-break:break-all; }}
  .finding footer {{ margin-top:8px; color:var(--muted); font-size:11px; }}
  .empty {{ color:var(--muted); }}
  .scroll {{ overflow-x:auto; }}
  table.art td, table.art th {{ vertical-align:top; }}
  table.art code {{ word-break:break-all; }}
  .chain {{ background:var(--card); border:1px solid var(--line);
    border-left:5px solid #b4232a; border-radius:8px; padding:12px 16px; margin:12px 0; }}
  .chain header {{ display:flex; gap:10px; align-items:center; flex-wrap:wrap; }}
  .pivot {{ font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;
    background:#b4232a; color:#fff; padding:2px 8px; border-radius:4px; }}
  .flow {{ font-size:13px; color:var(--fg); }}
  .arrow {{ color:var(--muted); }}
  .chain ul {{ margin:8px 0 0; }}
  .chain li {{ font-size:13px; }}
</style>
</head>
<body>
<div class="wrap">
  <h1>pcaptriage report</h1>
  <div class="sub">capture: <code>{_esc(pcap_name)}</code> &middot; generated {generated}</div>

  <div class="tiles">{sev_tiles}</div>

  {_narrative_html(narrative)}
  {_artifacts_html(artifacts or [])}

  <section>
    <h2>Findings</h2>
    {findings_html}
  </section>

  <section>
    <h2>Capture summary</h2>
    <p class="sub">{summary['connections']} connections &middot;
      {summary['distinct_hosts']} distinct hosts &middot;
      logs: {_esc(', '.join(summary['log_types']))}<br>
      {_esc(summary['time_span'])}</p>
    <div class="grid">
      <div>
        <h3>Top talkers</h3>
        <table><tr><th>Host</th><th>Conns</th></tr>{talkers_rows}</table>
      </div>
      <div>
        <h3>Top services</h3>
        <table><tr><th>Service</th><th>Conns</th></tr>{services_rows}</table>
      </div>
    </div>
  </section>
</div>
</body>
</html>
"""
