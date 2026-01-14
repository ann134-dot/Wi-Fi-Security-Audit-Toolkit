import json
from datetime import datetime
from typing import List, Optional

from .scanner import WiFiNetwork, to_jsonable
from .analyze import Finding

def render_markdown(results: List[tuple[WiFiNetwork, List[Finding]]], generated_at: str) -> str:
    lines = []
    lines.append(f"# Wi-Fi Security Audit Report\n")
    lines.append(f"- Generated at: **{generated_at}**\n")
    lines.append(f"- Scope: nearby Wi-Fi networks (authorized/lab use)\n")

    lines.append("## Networks Overview\n")
    lines.append("| SSID | BSSID | Vendor | Channel | Signal | RSSI | Encryption | WPS | Findings |")
    lines.append("|---|---|---|---:|---:|---:|---|---|---:|")

    for net, findings in results:
        vendor = net.vendor or "-"
        ch = net.channel if net.channel is not None else "-"
        sig = f"{net.signal_pct}%" if net.signal_pct is not None else "-"
        rssi = f"{net.rssi_dbm} dBm" if net.rssi_dbm is not None else "-"
        wps = "Yes" if net.wps is True else ("No" if net.wps is False else "Unknown")
        lines.append(f"| {escape_md(net.ssid)} | {net.bssid} | {escape_md(vendor)} | {ch} | {sig} | {rssi} | {net.encryption} | {wps} | {len(findings)} |")

    lines.append("\n## Findings & Recommendations\n")
    for net, findings in results:
        lines.append(f"### {escape_md(net.ssid)} ({net.bssid})\n")
        if not findings:
            lines.append("- No issues detected by current ruleset.\n")
            continue
        for f in findings:
            lines.append(f"- **[{f.severity}] {escape_md(f.title)}** — {escape_md(f.details)}")
            lines.append(f"  - Remediation: {escape_md(f.remediation)}")
        lines.append("")

    return "\n".join(lines)

def render_html(results: List[tuple[WiFiNetwork, List[Finding]]], generated_at: str) -> str:
    # Simple self-contained HTML (no external assets)
    rows = []
    for net, findings in results:
        vendor = net.vendor or "-"
        ch = net.channel if net.channel is not None else "-"
        sig = f"{net.signal_pct}%" if net.signal_pct is not None else "-"
        rssi = f"{net.rssi_dbm} dBm" if net.rssi_dbm is not None else "-"
        wps = "Yes" if net.wps is True else ("No" if net.wps is False else "Unknown")
        rows.append(f"""
        <tr>
          <td>{html(net.ssid)}</td>
          <td><code>{html(net.bssid)}</code></td>
          <td>{html(vendor)}</td>
          <td style="text-align:right">{ch}</td>
          <td style="text-align:right">{sig}</td>
          <td style="text-align:right">{rssi}</td>
          <td>{html(net.encryption)}</td>
          <td>{html(wps)}</td>
          <td style="text-align:right">{len(findings)}</td>
        </tr>
        """)

    findings_html = []
    for net, findings in results:
        findings_html.append(f"<h3>{html(net.ssid)} <small><code>{html(net.bssid)}</code></small></h3>")
        if not findings:
            findings_html.append("<p>No issues detected by current ruleset.</p>")
            continue
        findings_html.append("<ul>")
        for f in findings:
            findings_html.append(f"""
              <li>
                <strong>[{html(f.severity)}] {html(f.title)}</strong>
                <div>{html(f.details)}</div>
                <div><em>Remediation:</em> {html(f.remediation)}</div>
              </li>
            """)
        findings_html.append("</ul>")

    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Wi-Fi Security Audit Report</title>
  <style>
    body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin: 24px; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; vertical-align: top; }}
    th {{ background: #f5f5f5; text-align: left; }}
    code {{ background: #f3f3f3; padding: 2px 4px; border-radius: 4px; }}
    h1 {{ margin-top: 0; }}
    .meta {{ color: #555; }}
  </style>
</head>
<body>
  <h1>Wi-Fi Security Audit Report</h1>
  <p class="meta">Generated at: <strong>{html(generated_at)}</strong><br/>
  Scope: nearby Wi-Fi networks (authorized/lab use)</p>

  <h2>Networks Overview</h2>
  <table>
    <thead>
      <tr>
        <th>SSID</th><th>BSSID</th><th>Vendor</th><th>Channel</th><th>Signal</th><th>RSSI</th><th>Encryption</th><th>WPS</th><th>Findings</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>

  <h2>Findings & Recommendations</h2>
  {''.join(findings_html)}
</body>
</html>
"""

def write_json(path: str, nets: List[WiFiNetwork], generated_at: str) -> None:
    payload = {
        "generated_at": generated_at,
        "networks": to_jsonable(nets),
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

def escape_md(s: str) -> str:
    return (s or "").replace("|", "\\|").replace("\n", " ")

def html(s: str) -> str:
    s = s or ""
    return (s.replace("&", "&amp;")
              .replace("<", "&lt;")
              .replace(">", "&gt;")
              .replace('"', "&quot;")
              .replace("'", "&#39;"))
