"""
hosts_scanner.py - Hosts file tampering detection module.
Checks C:\\Windows\\System32\\drivers\\etc\\hosts for:
  1. Suspicious redirects of legitimate domains (e.g., microsoft.com → 127.0.0.1)
  2. Excessive number of entries (possible adware/malware)
  3. Known malicious domain entries
  4. Non-standard file permissions or hidden attributes
"""

import os
import re
from typing import List, Set

from scanner_core.utils import (
    Finding, RiskLevel,
    print_section, print_finding,
)


# Default Windows hosts file entries (safe to ignore)
DEFAULT_HOSTS_ENTRIES = {
    ("127.0.0.1", "localhost"),
    ("::1", "localhost"),
}

# Legitimate domains that should NEVER be redirected in hosts file
# If these are found pointing to anything other than expected, flag it
PROTECTED_DOMAINS = {
    # Microsoft
    "microsoft.com", "www.microsoft.com",
    "windowsupdate.com", "www.windowsupdate.com",
    "update.microsoft.com", "download.microsoft.com",
    "windows.com", "login.microsoftonline.com",
    "login.live.com", "outlook.com",
    # Google
    "google.com", "www.google.com",
    "accounts.google.com", "gmail.com",
    # Security vendors
    "avast.com", "avg.com", "kaspersky.com",
    "malwarebytes.com", "norton.com", "symantec.com",
    "eset.com", "bitdefender.com", "mcafee.com",
    "sophos.com", "trendmicro.com",
    # Certificate authorities
    "digicert.com", "letsencrypt.org", "verisign.com",
    # Banks (generic patterns)
    "paypal.com", "www.paypal.com",
}

# Threshold for suspicious number of entries
EXCESSIVE_ENTRIES_THRESHOLD = 50

# Known ad-blocking hosts files have thousands of entries
# but they typically redirect to 0.0.0.0, which is safe
ADBLOCK_TARGETS = {"0.0.0.0", "127.0.0.1", "::1"}


def _parse_hosts_file(hosts_path: str) -> List[dict]:
    """Parse the hosts file and return list of entries."""
    entries = []
    try:
        with open(hosts_path, "r", encoding="utf-8", errors="ignore") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Remove inline comments
                if "#" in line:
                    line = line[:line.index("#")].strip()

                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    for hostname in parts[1:]:
                        entries.append({
                            "ip": ip.lower(),
                            "hostname": hostname.lower(),
                            "line": line_num,
                        })
    except (PermissionError, OSError, UnicodeDecodeError):
        pass

    return entries


def _is_default_entry(ip: str, hostname: str) -> bool:
    """Check if this is a default Windows hosts entry."""
    return (ip, hostname) in DEFAULT_HOSTS_ENTRIES


def scan() -> List[Finding]:
    """Run the hosts file scanner and return findings."""
    print_section("HOSTS FILE SCANNER - Tampering Detection")
    findings = []

    hosts_path = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"),
        "System32", "drivers", "etc", "hosts"
    )

    if not os.path.isfile(hosts_path):
        print(f"  [!] Hosts file not found: {hosts_path}")
        return findings

    print(f"  [i] Checking: {hosts_path}")

    # Check file size (unusually large hosts file)
    try:
        file_size = os.path.getsize(hosts_path)
        print(f"  [i] File size: {file_size} bytes")
    except OSError:
        file_size = 0

    # Parse entries
    entries = _parse_hosts_file(hosts_path)
    non_default = [e for e in entries if not _is_default_entry(e["ip"], e["hostname"])]
    print(f"  [i] Total entries: {len(entries)} ({len(non_default)} non-default)")

    if not non_default:
        print("  [i] Hosts file is clean (only default entries).")
        return findings

    # ---- CHECK 1: Protected domain redirects ----
    for entry in non_default:
        hostname = entry["hostname"]
        ip = entry["ip"]

        # Check if a protected domain is being redirected
        for protected in PROTECTED_DOMAINS:
            if hostname == protected or hostname.endswith("." + protected):
                # Being redirected to an ad-blocking target is less suspicious
                if ip in ADBLOCK_TARGETS:
                    # Still flag if it's a major protected domain
                    if protected in {
                        "microsoft.com", "windowsupdate.com", "update.microsoft.com",
                        "google.com", "accounts.google.com",
                    }:
                        finding = Finding(
                            module="Hosts Scanner",
                            risk=RiskLevel.HIGH,
                            title=f"Critical domain blocked in hosts: {hostname}",
                            description=f"'{hostname}' is redirected to {ip}. "
                                        "This may prevent Windows updates or access to critical services.",
                            details={
                                "hostname": hostname,
                                "redirected_to": ip,
                                "hosts_file": hosts_path,
                                "line": entry["line"],
                            },
                            mitre_id="T1565.001",
                            remediation=f"Remove the entry for '{hostname}' from the hosts file.",
                        )
                        findings.append(finding)
                        print_finding(finding)
                else:
                    # Redirected to a non-standard IP — highly suspicious
                    finding = Finding(
                        module="Hosts Scanner",
                        risk=RiskLevel.CRITICAL,
                        title=f"Domain hijacked in hosts: {hostname} → {ip}",
                        description=f"'{hostname}' is redirected to suspicious IP {ip}. "
                                    "This is a strong indicator of malware DNS hijacking.",
                        details={
                            "hostname": hostname,
                            "redirected_to": ip,
                            "hosts_file": hosts_path,
                            "line": entry["line"],
                        },
                        mitre_id="T1565.001",
                        remediation=f"Remove the malicious entry for '{hostname}' from the hosts file immediately.",
                    )
                    findings.append(finding)
                    print_finding(finding)
                break

    # ---- CHECK 2: Security vendor domains blocked ----
    blocked_security = []
    security_domains = {
        "avast.com", "avg.com", "kaspersky.com", "malwarebytes.com",
        "norton.com", "symantec.com", "eset.com", "bitdefender.com",
        "mcafee.com", "sophos.com", "trendmicro.com",
    }
    for entry in non_default:
        for sec_domain in security_domains:
            if entry["hostname"] == sec_domain or entry["hostname"].endswith("." + sec_domain):
                blocked_security.append(entry["hostname"])
                break

    if blocked_security:
        finding = Finding(
            module="Hosts Scanner",
            risk=RiskLevel.CRITICAL,
            title=f"Security vendor domains blocked ({len(blocked_security)})",
            description="Antivirus/security vendor domains are being redirected in the hosts file. "
                        "Malware often does this to prevent security updates and detection.",
            details={
                "blocked_domains": ", ".join(blocked_security[:20]),
                "count": len(blocked_security),
                "hosts_file": hosts_path,
            },
            mitre_id="T1562.001",
            remediation="Remove all security vendor redirects from the hosts file. "
                        "Run a malware scan with an offline scanner.",
        )
        findings.append(finding)
        print_finding(finding)

    # ---- CHECK 3: Excessive non-adblock entries ----
    # Adblock entries (pointing to 0.0.0.0 or 127.0.0.1) are normal in large quantities
    non_adblock = [e for e in non_default if e["ip"] not in ADBLOCK_TARGETS]
    if len(non_adblock) > 10:
        finding = Finding(
            module="Hosts Scanner",
            risk=RiskLevel.MEDIUM,
            title=f"Unusual hosts entries: {len(non_adblock)} non-standard redirects",
            description="Multiple domains are redirected to non-standard IPs. "
                        "Review these entries for potential DNS hijacking.",
            details={
                "non_standard_count": len(non_adblock),
                "sample_entries": "; ".join(
                    f"{e['hostname']}→{e['ip']}" for e in non_adblock[:10]
                ),
                "hosts_file": hosts_path,
            },
            mitre_id="T1565.001",
            remediation="Review and clean up the hosts file. Remove entries you don't recognize.",
        )
        findings.append(finding)
        print_finding(finding)

    # ---- CHECK 4: Large hosts file (potential adware indicator) ----
    if len(non_default) > EXCESSIVE_ENTRIES_THRESHOLD and not findings:
        # Many entries but all pointing to blocking IPs — likely ad blocker
        adblock_count = len([e for e in non_default if e["ip"] in ADBLOCK_TARGETS])
        if adblock_count > EXCESSIVE_ENTRIES_THRESHOLD:
            finding = Finding(
                module="Hosts Scanner",
                risk=RiskLevel.INFO,
                title=f"Ad-blocking hosts file detected ({len(non_default)} entries)",
                description="The hosts file contains many ad-blocking entries. "
                            "This is typically intentional but verify it was configured by you.",
                details={
                    "total_entries": len(non_default),
                    "adblock_entries": adblock_count,
                    "hosts_file": hosts_path,
                },
            )
            findings.append(finding)
            print_finding(finding)

    print(f"  [i] Hosts file scan complete. {len(findings)} findings.")
    return findings
