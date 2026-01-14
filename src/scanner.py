import json
import subprocess
from dataclasses import dataclass, asdict
from typing import List, Optional

from .utils import freq_to_channel_mhz, normalize_mac

@dataclass
class WiFiNetwork:
    ssid: str
    bssid: str
    channel: Optional[int]
    rssi_dbm: Optional[int]     # may be None depending on source
    signal_pct: Optional[int]   # 0-100 if available
    encryption: str             # e.g., "OPEN", "WEP", "WPA2", "WPA3", "WPA2/WPA3", "UNKNOWN"
    wps: Optional[bool]         # None if not visible
    vendor: Optional[str] = None

def _run(cmd: List[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)

def scan_nmcli() -> List[WiFiNetwork]:
    """
    Uses NetworkManager's nmcli to list APs.
    nmcli output does not reliably expose WPS; we set wps=None here.
    """
    # -t = terse; fields separated by ':'
    fields = "SSID,BSSID,FREQ,SIGNAL,SECURITY"
    cp = _run(["nmcli", "-t", "-f", fields, "dev", "wifi", "list"])
    if cp.returncode != 0 or not cp.stdout.strip():
        return []

    nets: List[WiFiNetwork] = []
    for line in cp.stdout.splitlines():
        # nmcli terse uses ':' as field separator, but SSID can also contain ':'.
        # Safer approach: split from the right knowing last 4 fields are fixed.
        # Format roughly: SSID:BSSID:FREQ:SIGNAL:SECURITY
        parts = line.split(":")
        if len(parts) < 5:
            continue
        security = parts[-1].strip()
        signal = parts[-2].strip()
        freq = parts[-3].strip()
        bssid = parts[-4].strip()
        ssid = ":".join(parts[:-4]).strip()  # rejoin SSID part

        try:
            freq_mhz = int(freq) if freq else None
        except ValueError:
            freq_mhz = None

        try:
            sig_pct = int(signal) if signal else None
        except ValueError:
            sig_pct = None

        enc = classify_encryption_from_nmcli(security)
        ch = freq_to_channel_mhz(freq_mhz)

        nets.append(WiFiNetwork(
            ssid=ssid if ssid else "<hidden>",
            bssid=normalize_mac(bssid),
            channel=ch,
            rssi_dbm=None,          # nmcli doesn't always show dBm
            signal_pct=sig_pct,
            encryption=enc,
            wps=None
        ))

    return nets

def classify_encryption_from_nmcli(security: str) -> str:
    s = (security or "").upper()
    if not s or s in {"--", "NONE"}:
        return "OPEN"
    if "WEP" in s:
        return "WEP"
    has_wpa2 = "WPA2" in s or "RSN" in s
    has_wpa3 = "WPA3" in s or "SAE" in s
    if has_wpa2 and has_wpa3:
        return "WPA2/WPA3"
    if has_wpa3:
        return "WPA3"
    if has_wpa2 or "WPA" in s:
        return "WPA2"
    return "UNKNOWN"

def scan_iw(interface: Optional[str] = None) -> List[WiFiNetwork]:
    """
    Fallback scan using `iw`. Can sometimes reveal WPS elements.
    Requires: sudo privileges depending on system configuration.
    """
    cmd = ["iw"]
    if interface:
        cmd += ["dev", interface]
    else:
        cmd += ["dev"]
    cmd += ["scan"]

    cp = _run(cmd)
    if cp.returncode != 0 or not cp.stdout.strip():
        return []

    nets: List[WiFiNetwork] = []
    current = None

    # Very lightweight parser for iw scan output
    for line in cp.stdout.splitlines():
        line = line.strip()

        if line.startswith("BSS "):
            # Commit previous
            if current:
                nets.append(current)
            bssid = line.split()[1].split("(")[0].strip()
            current = WiFiNetwork(
                ssid="<hidden>",
                bssid=normalize_mac(bssid),
                channel=None,
                rssi_dbm=None,
                signal_pct=None,
                encryption="UNKNOWN",
                wps=None
            )
            continue

        if current is None:
            continue

        if line.startswith("SSID:"):
            ssid = line.replace("SSID:", "", 1).strip()
            current.ssid = ssid if ssid else "<hidden>"

        if line.startswith("signal:"):
            # signal: -56.00 dBm
            try:
                val = float(line.split()[1])
                current.rssi_dbm = int(round(val))
            except Exception:
                pass

        if line.startswith("freq:"):
            try:
                f = int(line.split()[1])
                current.channel = freq_to_channel_mhz(f)
            except Exception:
                pass

        # Encryption inference
        if "RSN:" in line:
            # RSN implies WPA2/3; we'll refine if we see SAE later
            if current.encryption == "UNKNOWN":
                current.encryption = "WPA2"
        if "WPA:" in line:
            if current.encryption == "UNKNOWN":
                current.encryption = "WPA2"
        if "SAE" in line:
            # SAE is WPA3-Personal
            current.encryption = "WPA3"
        if "WEP" in line:
            current.encryption = "WEP"

        # WPS presence (best-effort)
        if line.startswith("WPS:") or "Wi-Fi Protected Setup" in line:
            current.wps = True

    if current:
        nets.append(current)

    # If wps was never seen, keep None (unknown) rather than False
    return nets

def scan_networks(prefer_nmcli: bool = True, interface: Optional[str] = None) -> List[WiFiNetwork]:
    if prefer_nmcli:
        nets = scan_nmcli()
        if nets:
            return nets
        return scan_iw(interface=interface)
    else:
        nets = scan_iw(interface=interface)
        if nets:
            return nets
        return scan_nmcli()

def to_jsonable(nets: List[WiFiNetwork]) -> List[dict]:
    return [asdict(n) for n in nets]
