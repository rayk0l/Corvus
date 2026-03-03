"""
service_scanner.py - Windows service scanner module.
Context-aware: whitelists OS-native paths (including Windows Defender),
checks signatures before flagging, and respects known vendor services.
"""

import os
import re
import subprocess
from typing import List

import psutil

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    check_file_signature, is_os_native_path, is_known_dev_tool,
    print_section, print_finding,
)


# Suspicious patterns in service binary paths or commands
SUSPICIOUS_PATTERNS = [
    (r"-enc\s+[A-Za-z0-9+/=]{10,}", "Encoded PowerShell command"),
    (r"frombase64string", "Base64 decoding"),
    (r"\bIEX\b.*\bdownload", "IEX with download"),
    (r"downloadstring", "DownloadString"),
    (r"bitsadmin\s+/transfer", "BitsAdmin transfer"),
    (r"certutil\s+-urlcache", "Certutil URL download"),
    (r"mshta\s+http", "MSHTA remote execution"),
    (r"regsvr32\s+/s\s+/n\s+/u", "Regsvr32 bypass"),
]

# Known safe service display name patterns (lowercase, partial match)
KNOWN_SAFE_SERVICES = {
    "windows update", "windows defender", "windows search", "windows audio",
    "windows time", "windows event log", "windows firewall", "windows installer",
    "print spooler", "dns client", "dhcp client", "network connections",
    "task scheduler", "security center", "server", "workstation",
    "remote desktop", "remote procedure call", "plug and play",
    "cryptographic services", "background intelligent transfer",
    "application information", "com+ event system", "system events broker",
    "diagnostic", "superfetch", "sysmain", "wmi performance adapter",
    "defender", "antivirus", "microsoft defender", "mdcoresvc",
    "microsoft defender antivirus", "windows defender antivirus",
    "defender core", "security health",
    # Cloud/AV vendors
    "mcafee", "norton", "symantec", "kaspersky", "sophos",
    "trend micro", "eset", "avast", "avg", "malwarebytes",
    "crowdstrike", "carbon black", "sentinelone", "cylance",
    "cortex", "falcon", "tamper protection",
}

# Known safe service path patterns
SAFE_SERVICE_PATHS = [
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\",
    "c:\\programdata\\packages\\",
]


def _extract_binary_path(image_path: str) -> str:
    """Extract the actual binary path from a service ImagePath."""
    path = image_path.strip()
    if path.startswith('"'):
        end = path.find('"', 1)
        if end > 0:
            return path[1:end]
    else:
        parts = path.split()
        if parts:
            return parts[0]
    return path


def _get_services_info() -> List[dict]:
    """Get detailed service information."""
    services = []
    try:
        result = subprocess.run(
            ["wmic", "service", "get",
             "Name,DisplayName,PathName,StartMode,State,Description,StartName",
             "/format:csv"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace"
        )
        lines = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]

        if len(lines) > 1:
            header = lines[0].split(",")
            for line in lines[1:]:
                parts = line.split(",")
                if len(parts) >= len(header):
                    svc = {}
                    for i, h in enumerate(header):
                        svc[h.strip()] = parts[i].strip() if i < len(parts) else ""
                    services.append(svc)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        try:
            for svc in psutil.win_service_iter():
                try:
                    info = svc.as_dict()
                    services.append({
                        "Name": info.get("name", ""),
                        "DisplayName": info.get("display_name", ""),
                        "PathName": info.get("binpath", ""),
                        "StartMode": info.get("start_type", ""),
                        "State": info.get("status", ""),
                        "Description": "",
                        "StartName": info.get("username", ""),
                    })
                except Exception:
                    pass
        except Exception:
            pass

    return services


def scan() -> List[Finding]:
    """Run the service scanner and return findings."""
    print_section("SERVICE SCANNER - Context-Aware Service Detection")
    findings = []

    print("  [i] Enumerating Windows services...")
    services = _get_services_info()
    print(f"  [i] Found {len(services)} services")

    for svc in services:
        name = svc.get("Name", "")
        display = svc.get("DisplayName", "")
        path_name = svc.get("PathName", "")

        if not path_name:
            continue

        # ---- FILTER: Skip known safe services ----
        display_lower = display.lower()
        name_lower = name.lower()
        if any(safe in display_lower or safe in name_lower for safe in KNOWN_SAFE_SERVICES):
            continue

        binary_path = _extract_binary_path(path_name)
        path_lower = path_name.lower()
        binary_lower = binary_path.lower()

        # ---- FILTER: Skip OS-native and known safe paths ----
        if any(binary_lower.startswith(sp) for sp in SAFE_SERVICE_PATHS):
            continue

        if is_os_native_path(binary_path):
            continue

        # ---- FILTER: Skip known developer tool paths ----
        if is_known_dev_tool("", binary_path):
            continue

        start_mode = svc.get("StartMode", "")
        state = svc.get("State", "")
        start_name = svc.get("StartName", "")

        # ---- CHECK 1: Suspicious command patterns in service path ----
        for pattern, label in SUSPICIOUS_PATTERNS:
            if re.search(pattern, path_lower, re.IGNORECASE):
                finding = Finding(
                    module="Service Scanner",
                    risk=RiskLevel.HIGH,
                    title=f"Suspicious service command: {display or name}",
                    description=f"Service contains attack pattern: {label}",
                    details={
                        "service_name": name,
                        "display_name": display,
                        "binary_path": path_name[:500],
                        "pattern": label,
                        "start_mode": start_mode,
                        "state": state,
                        "run_as": start_name,
                    },
                    mitre_id="T1543.003",
                    remediation=f"Stop and delete the suspicious service: sc stop {name} && sc delete {name}",
                )
                findings.append(finding)
                print_finding(finding)
                break

        # ---- CHECK 2: Service from user-writable suspicious dir ----
        suspicious_locs = ["\\appdata\\", "\\temp\\", "\\tmp\\",
                           "\\downloads\\", "\\users\\public\\"]
        if any(loc in binary_lower for loc in suspicious_locs):
            # Check signature before flagging
            if os.path.isfile(binary_path):
                sig = check_file_signature(binary_path)
                if not sig.get("trusted"):
                    risk = RiskLevel.HIGH if not sig.get("signed") else RiskLevel.MEDIUM
                    finding = Finding(
                        module="Service Scanner",
                        risk=risk,
                        title=f"Service from suspicious path: {display or name}",
                        description="Service binary is in a user-writable directory and not signed by a trusted vendor.",
                        details={
                            "service_name": name,
                            "display_name": display,
                            "binary_path": path_name[:500],
                            "signed": sig.get("signed", False),
                            "signer": sig.get("signer", "Unknown"),
                            "start_mode": start_mode,
                            "state": state,
                        },
                        mitre_id="T1543.003",
                        remediation=f"Investigate the service binary. Stop and delete if unauthorized: sc stop {name} && sc delete {name}",
                    )
                    findings.append(finding)
                    print_finding(finding)

    print(f"  [i] Service scan complete. {len(findings)} findings.")
    return findings
