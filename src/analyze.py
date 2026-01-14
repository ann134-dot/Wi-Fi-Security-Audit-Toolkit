from dataclasses import dataclass
from typing import List, Optional

from .scanner import WiFiNetwork

@dataclass
class Finding:
    severity: str   # "LOW" | "MEDIUM" | "HIGH"
    title: str
    details: str
    remediation: str

def analyze_network(net: WiFiNetwork) -> List[Finding]:
    findings: List[Finding] = []

    enc = (net.encryption or "UNKNOWN").upper()

    if enc == "OPEN":
        findings.append(Finding(
            severity="HIGH",
            title="Open network (no encryption)",
            details="Traffic can be intercepted/modified by anyone within range.",
            remediation="Enable WPA2-AES or WPA3-Personal; use a strong passphrase and disable open guest access unless required."
        ))

    if enc == "WEP":
        findings.append(Finding(
            severity="HIGH",
            title="WEP encryption detected",
            details="WEP is obsolete and can be broken quickly.",
            remediation="Migrate to WPA2-AES or WPA3-Personal immediately."
        ))

    # Best-effort TKIP detection: nmcli SECURITY sometimes includes 'TKIP'
    # If your scan source provides it in encryption string, we can catch it:
    if "TKIP" in enc:
        findings.append(Finding(
            severity="HIGH",
            title="WPA2-TKIP detected",
            details="TKIP is deprecated and weaker than AES/CCMP.",
            remediation="Force WPA2-AES (CCMP) or WPA3; disable TKIP on the AP."
        ))

    if net.wps is True:
        findings.append(Finding(
            severity="MEDIUM",
            title="WPS enabled/visible",
            details="WPS increases attack surface and is often unnecessary.",
            remediation="Disable WPS on the access point unless you have a specific operational need."
        ))

    if enc == "UNKNOWN":
        findings.append(Finding(
            severity="LOW",
            title="Encryption could not be determined",
            details="Scanner could not confidently classify security settings.",
            remediation="Re-scan using `iw` (may require sudo) or verify encryption in AP settings."
        ))

    # WPA2 is fine but WPA3 is preferred
    if enc == "WPA2":
        findings.append(Finding(
            severity="LOW",
            title="WPA2 detected (consider WPA3 if available)",
            details="WPA2-AES remains acceptable, but WPA3 provides stronger protection and modern features.",
            remediation="If hardware supports it, enable WPA3-Personal (SAE) or WPA2/WPA3 transition mode."
        ))

    return findings

def analyze_all(nets: List[WiFiNetwork]) -> List[tuple[WiFiNetwork, List[Finding]]]:
    return [(n, analyze_network(n)) for n in nets]
