import re
from typing import Optional

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")

def normalize_mac(mac: str) -> str:
    mac = mac.strip().lower()
    return mac

def is_mac(mac: str) -> bool:
    return bool(MAC_RE.match(mac.strip()))

def freq_to_channel_mhz(freq_mhz: Optional[int]) -> Optional[int]:
    """
    Convert frequency (MHz) to Wi-Fi channel for common 2.4/5/6 GHz ranges.
    """
    if freq_mhz is None:
        return None
    f = int(freq_mhz)

    # 2.4 GHz: 2412 + 5*(ch-1)
    if 2412 <= f <= 2472:
        return (f - 2412) // 5 + 1
    if f == 2484:
        return 14

    # 5 GHz common
    if 5000 <= f <= 5900:
        return (f - 5000) // 5

    # 6 GHz (approx; depends on regulatory domain)
    if 5925 <= f <= 7125:
        return (f - 5950) // 5

    return None

def clamp_int(value: Optional[int], lo: int, hi: int) -> Optional[int]:
    if value is None:
        return None
    return max(lo, min(hi, int(value)))
