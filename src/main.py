import argparse
import os
from datetime import datetime

from .scanner import scan_networks, WiFiNetwork
from .oui import OUILookup
from .analyze import analyze_all
from .report import render_markdown, render_html, write_json

def attach_vendors(nets: list[WiFiNetwork], oui_csv: str | None) -> None:
    if not oui_csv:
        return
    if not os.path.exists(oui_csv):
        print(f"[!] OUI CSV not found: {oui_csv} (skipping vendor lookup)")
        return
    lookup = OUILookup()
    lookup.load_csv(oui_csv)
    for n in nets:
        n.vendor = lookup.vendor_for_bssid(n.bssid)

def main() -> int:
    p = argparse.ArgumentParser(
        prog="wifi-audit",
        description="Wi-Fi Security Audit Toolkit (authorized/lab use only)."
    )
    p.add_argument("--out-dir", default="out", help="Output directory for reports (default: out)")
    p.add_argument("--interface", default=None, help="Wireless interface for iw scan (e.g., wlan0)")
    p.add_argument("--prefer", choices=["nmcli", "iw"], default="nmcli", help="Preferred scanner backend")
    p.add_argument("--oui-csv", default="data/oui_sample.csv", help="Offline OUI CSV (prefix,vendor)")
    p.add_argument("--json", action="store_true", help="Also export JSON (for SIEM/log analysis practice)")
    args = p.parse_args()

    prefer_nmcli = args.prefer == "nmcli"
    nets = scan_networks(prefer_nmcli=prefer_nmcli, interface=args.interface)

    if not nets:
        print("[!] No networks found. Try:")
        print("    - ensuring Wi-Fi is enabled")
        print("    - running with --prefer iw (may need sudo)")
        print("    - specifying --interface wlan0")
        return 2

    attach_vendors(nets, args.oui_csv)

    results = analyze_all(nets)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    os.makedirs(args.out_dir, exist_ok=True)
    md_path = os.path.join(args.out_dir, "wifi_audit_report.md")
    html_path = os.path.join(args.out_dir, "wifi_audit_report.html")
    json_path = os.path.join(args.out_dir, "wifi_audit_report.json")

    md = render_markdown(results, ts)
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(md)

    html = render_html(results, ts)
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(html)

    if args.json:
        write_json(json_path, nets, ts)

    print(f"[+] Wrote: {md_path}")
    print(f"[+] Wrote: {html_path}")
    if args.json:
        print(f"[+] Wrote: {json_path}")

    return 0

if __name__ == "__main__":
    raise SystemExit(main())
