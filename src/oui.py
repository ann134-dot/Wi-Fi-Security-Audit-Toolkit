import csv
from dataclasses import dataclass
from typing import Dict, Optional

from .utils import normalize_mac

@dataclass(frozen=True)
class OUIRecord:
    prefix: str  # "aa:bb:cc"
    vendor: str

class OUILookup:
    """
    Offline OUI lookup from a CSV file with columns:
    prefix,vendor
    Example prefix formats accepted:
      aa:bb:cc
      aabbcc
      AA-BB-CC
    """
    def __init__(self) -> None:
        self._map: Dict[str, str] = {}

    @staticmethod
    def _normalize_prefix(prefix: str) -> str:
        p = prefix.strip().lower().replace("-", ":")
        if ":" not in p and len(p) >= 6:
            p = ":".join([p[0:2], p[2:4], p[4:6]])
        parts = p.split(":")
        if len(parts) < 3:
            return p
        return ":".join(parts[:3])

    def load_csv(self, path: str) -> None:
        with open(path, "r", encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                pref = self._normalize_prefix(row.get("prefix", ""))
                vendor = (row.get("vendor") or "").strip()
                if pref and vendor:
                    self._map[pref] = vendor

    def vendor_for_bssid(self, bssid: str) -> Optional[str]:
        mac = normalize_mac(bssid)
        parts = mac.split(":")
        if len(parts) < 3:
            return None
        key = ":".join(parts[:3])
        return self._map.get(key)
