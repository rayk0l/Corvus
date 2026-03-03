"""
port_scanner.py - Open port scanner module.
Context-aware: skips known developer tools, ephemeral ports, and
trusted-signed processes. Only flags genuinely suspicious listeners.
"""

import os
from typing import List, Dict, Set

import psutil

from scanner_core.utils import (
    Finding, RiskLevel,
    get_resource_path, check_file_signature,
    is_known_dev_tool, is_suspicious_userland_path,
    print_section, print_finding,
)

# Well-known legitimate ports (skip entirely)
LEGITIMATE_PORTS = {
    80, 443, 445, 135, 139, 53, 88, 389, 636, 3389, 5985, 5986,
    1433, 3306, 5432,  # DB ports
    25, 110, 143, 587, 993, 995,  # Mail
    21, 22, 23,  # FTP/SSH/Telnet
    8080, 8443,  # Common web proxies
    5040,  # Windows WFP
}

# Known high-risk backdoor/RAT ports
HIGH_RISK_PORTS = {
    4444: "Metasploit default handler",
    4445: "Metasploit secondary handler",
    5555: "Android ADB / backdoor",
    31337: "Back Orifice",
    31338: "Back Orifice 2",
    12345: "NetBus",
    12346: "NetBus",
    20034: "NetBus Pro",
    27374: "SubSeven",
    54321: "Back Orifice 2000",
    1604: "DarkComet",
    3150: "DeepThroat",
    3460: "Poison Ivy",
    5110: "ProRat",
    50050: "Cobalt Strike Team Server",
    1337: "Common leet port",
}

# Medium risk ports
MEDIUM_RISK_PORTS = {
    6666: "IRC backdoor",
    6667: "IRC C2",
    6668: "IRC C2",
    6669: "IRC C2",
    7777: "Tini backdoor",
    9999: "Common backdoor",
    65535: "Common backdoor test port",
    19283: "SilverRAT",
    3333: "Crypto mining (Stratum)",
    5556: "Crypto mining pool",
    14444: "XMR mining pool",
    14433: "XMR mining pool",
    45700: "XMR mining pool",
}


def _get_process_info(pid: int) -> Dict:
    """Get process info for a PID."""
    try:
        proc = psutil.Process(pid)
        return {
            "name": proc.name(),
            "exe": proc.exe() or "",
        }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {"name": "Unknown", "exe": ""}


def scan() -> List[Finding]:
    """Run the open port scanner and return findings."""
    print_section("OPEN PORT SCANNER - Suspicious Listening Port Detection")
    findings = []

    # Get all listening connections
    try:
        connections = psutil.net_connections(kind="tcp")
    except psutil.AccessDenied:
        print("  [!] Access denied. Run as Administrator for full port visibility.")
        connections = []

    # Filter for LISTEN state only
    listening = [c for c in connections if c.status == "LISTEN"]
    print(f"  [i] Found {len(listening)} listening TCP ports")

    reported_ports: Set[int] = set()

    for conn in listening:
        port = conn.laddr.port
        bind_addr = conn.laddr.ip
        pid = conn.pid or 0

        if port in reported_ports:
            continue

        # Skip legitimate ports
        if port in LEGITIMATE_PORTS:
            continue

        # Skip Windows ephemeral ports (49152-65535) unless known backdoor
        if port >= 49152 and port not in HIGH_RISK_PORTS and port not in MEDIUM_RISK_PORTS:
            continue

        proc_info = _get_process_info(pid)
        proc_name = proc_info["name"]
        proc_path = proc_info["exe"]

        # Skip known developer tools
        if is_known_dev_tool(proc_name, proc_path):
            continue

        # Skip OS system processes
        system_procs = {"svchost.exe", "system", "lsass.exe", "services.exe",
                        "wininit.exe", "spoolsv.exe", "searchindexer.exe",
                        "msdtc.exe", "lsm.exe", "smss.exe"}
        if proc_name.lower() in system_procs:
            continue

        # Skip trusted-signed binaries
        if proc_path:
            sig = check_file_signature(proc_path)
            if sig.get("trusted"):
                continue

        # ---- CHECK 1: Known high-risk backdoor port ----
        if port in HIGH_RISK_PORTS:
            reported_ports.add(port)
            desc = HIGH_RISK_PORTS[port]
            finding = Finding(
                module="Port Scanner",
                risk=RiskLevel.HIGH,
                title=f"Backdoor port {port} open: {desc}",
                description=f"Port {port} ({desc}) is listening. Known backdoor/RAT port.",
                details={
                    "port": port,
                    "description": desc,
                    "bind_address": bind_addr,
                    "process": proc_name,
                    "process_path": proc_path,
                    "pid": pid,
                },
                mitre_id="T1571",
                remediation=f"Kill the process (PID {pid}) listening on port {port}. Investigate for backdoor/RAT activity.",
            )
            findings.append(finding)
            print_finding(finding)
            continue

        # ---- CHECK 2: Known medium-risk port ----
        if port in MEDIUM_RISK_PORTS:
            reported_ports.add(port)
            desc = MEDIUM_RISK_PORTS[port]
            finding = Finding(
                module="Port Scanner",
                risk=RiskLevel.MEDIUM,
                title=f"Suspicious port {port} open: {desc}",
                description=f"Port {port} ({desc}) is listening.",
                details={
                    "port": port,
                    "description": desc,
                    "bind_address": bind_addr,
                    "process": proc_name,
                    "process_path": proc_path,
                    "pid": pid,
                },
                mitre_id="T1571",
                remediation=f"Investigate the process on port {port}. Close the port if unauthorized.",
            )
            findings.append(finding)
            print_finding(finding)
            continue

        # ---- CHECK 3: Unsigned process from suspicious path listening ----
        if proc_path and is_suspicious_userland_path(proc_path) and port < 49152:
            sig = check_file_signature(proc_path)
            if not sig.get("signed"):
                reported_ports.add(port)
                finding = Finding(
                    module="Port Scanner",
                    risk=RiskLevel.MEDIUM,
                    title=f"Unsigned listener on port {port}: {proc_name}",
                    description="Unsigned binary from user directory is listening on a port.",
                    details={
                        "port": port,
                        "bind_address": bind_addr,
                        "process": proc_name,
                        "process_path": proc_path,
                        "pid": pid,
                        "signed": False,
                    },
                    mitre_id="T1571",
                    remediation=f"Investigate the unsigned process '{proc_name}'. Block port {port} if unauthorized.",
                )
                findings.append(finding)
                print_finding(finding)

    print(f"  [i] Port scan complete. {len(findings)} findings.")
    return findings
