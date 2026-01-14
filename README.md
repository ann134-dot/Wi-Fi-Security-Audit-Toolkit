# Wi-Fi-Security-Audit-Toolkit
 Python-based wireless security assessment tool that enumerates Wi-Fi networks, analyzes encryption and configuration weaknesses, and produces JSON/Markdown reports for security auditing and documentation in lab-only scenarios

## Features
- Extracts: SSID, BSSID, channel, signal, encryption (WPA2/WPA3 best-effort), WPS presence (if visible), vendor via **offline OUI lookup**
- Flags misconfigs: open networks, WEP, WPA2-TKIP (best-effort), WPS enabled (if visible)
- Outputs: Markdown + HTML reports; optional JSON export

## Requirements
- Linux recommended
- `nmcli` (NetworkManager) for scanning (default)
- Fallback: `iw` scanning (may require `sudo`)

## Usage
```bash
python -m src.main --out-dir out --prefer nmcli --json
# Or use iw (may need sudo):
sudo python -m src.main --prefer iw --interface wlan0 --json