"""
network_scanner.py - Network connection analysis module.
Context-aware detection: trusts signed developer tools on HTTPS,
only flags genuinely suspicious outbound connections.
"""

import os
from typing import List, Set
from ipaddress import ip_address, IPv4Address, IPv6Address

import psutil

from scanner_core.utils import (
    Finding, RiskLevel,
    load_ioc_file, check_file_signature,
    is_known_dev_tool, is_suspicious_userland_path,
    print_section, print_finding,
)

# Processes that should NEVER be making external connections
INHERENTLY_SUSPICIOUS_NET_PROCESSES = {
    "mshta.exe", "regsvr32.exe", "certutil.exe",
    "bitsadmin.exe", "msiexec.exe", "rundll32.exe",
}

# wscript/cscript are suspicious if making NON-443 connections
SCRIPTING_ENGINES = {"wscript.exe", "cscript.exe"}


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address is private/reserved."""
    try:
        ip = ip_address(ip_str)
        return ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local
    except ValueError:
        return True


def _get_process_info(pid: int) -> dict:
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
    """Run the network scanner and return findings."""
    print_section("NETWORK SCANNER - Context-Aware Connection Analysis")
    findings = []

    bad_ips = load_ioc_file("bad_ips.txt")
    print(f"  [i] Loaded {len(bad_ips)} known malicious IPs")

    try:
        connections = psutil.net_connections(kind="tcp")
    except psutil.AccessDenied:
        print("  [!] Access denied reading connections. Run as Administrator.")
        connections = []

    established = [c for c in connections if c.status == "ESTABLISHED" and c.raddr]
    print(f"  [i] Analyzing {len(established)} active TCP connections")

    reported: Set[str] = set()

    for conn in established:
        remote_ip = conn.raddr.ip
        remote_port = conn.raddr.port
        pid = conn.pid or 0

        # Skip private/local IPs
        if _is_private_ip(remote_ip):
            continue

        proc_info = _get_process_info(pid)
        proc_name = proc_info["name"]
        proc_path = proc_info["exe"]
        name_lower = proc_name.lower()

        report_key = f"{name_lower}:{remote_ip}"
        if report_key in reported:
            continue

        # ---- CHECK 1: Known malicious IP (always CRITICAL) ----
        if remote_ip.lower() in bad_ips:
            reported.add(report_key)
            finding = Finding(
                module="Network Scanner",
                risk=RiskLevel.CRITICAL,
                title=f"Connection to known malicious IP: {remote_ip}",
                description=f"Process '{proc_name}' is connected to a known C2/malicious IP.",
                details={
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process": proc_name,
                    "process_path": proc_path,
                    "pid": pid,
                },
                mitre_id="T1071",
                remediation="Kill the process immediately. Block the IP in the firewall. Investigate the system for compromise.",
            )
            findings.append(finding)
            print_finding(finding)
            continue

        # ---- Skip known developer tools entirely ----
        if is_known_dev_tool(proc_name, proc_path):
            continue

        # ---- Skip signed + trusted binaries ----
        if proc_path:
            sig = check_file_signature(proc_path)
            if sig.get("trusted"):
                continue

        # ---- CHECK 2: Inherently suspicious processes with network ----
        if name_lower in INHERENTLY_SUSPICIOUS_NET_PROCESSES:
            reported.add(report_key)
            finding = Finding(
                module="Network Scanner",
                risk=RiskLevel.HIGH,
                title=f"Suspicious process with network: {proc_name} → {remote_ip}",
                description=f"{proc_name} should not be making outbound connections. Possible LOLBin abuse.",
                details={
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process": proc_name,
                    "process_path": proc_path,
                    "pid": pid,
                },
                mitre_id="T1218",
                remediation="Kill the process. Investigate why this system binary is making outbound connections.",
            )
            findings.append(finding)
            print_finding(finding)
            continue

        # ---- CHECK 3: Script engines on non-HTTPS ports ----
        if name_lower in SCRIPTING_ENGINES and remote_port != 443:
            reported.add(report_key)
            finding = Finding(
                module="Network Scanner",
                risk=RiskLevel.MEDIUM,
                title=f"Script engine outbound: {proc_name} → {remote_ip}:{remote_port}",
                description=f"Script engine connecting on non-HTTPS port.",
                details={
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "process": proc_name,
                    "process_path": proc_path,
                    "pid": pid,
                },
                mitre_id="T1059.005",
                remediation="Kill the script engine process. Investigate the script source and its network target.",
            )
            findings.append(finding)
            print_finding(finding)
            continue

        # ---- CHECK 4: Unsigned binary from suspicious path with network ----
        if proc_path and is_suspicious_userland_path(proc_path):
            sig = check_file_signature(proc_path)
            if not sig.get("signed"):
                reported.add(report_key)
                finding = Finding(
                    module="Network Scanner",
                    risk=RiskLevel.MEDIUM,
                    title=f"Unsigned process from user path: {proc_name} → {remote_ip}",
                    description="Unsigned binary from user-writable directory with external connection.",
                    details={
                        "remote_ip": remote_ip,
                        "remote_port": remote_port,
                        "process": proc_name,
                        "process_path": proc_path,
                        "pid": pid,
                        "signed": False,
                    },
                    mitre_id="T1036",
                    remediation="Investigate the unsigned process. Block outbound connections if unauthorized.",
                )
                findings.append(finding)
                print_finding(finding)

    print(f"  [i] Network scan complete. {len(findings)} findings.")
    return findings
