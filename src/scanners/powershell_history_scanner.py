"""
powershell_history_scanner.py - PSReadLine history analysis module.
Scans the PowerShell command history file for evidence of:
  1. Known attack commands (mimikatz, Invoke-*, credential dump)
  2. Encoded/obfuscated commands (-enc, -e, base64)
  3. Download cradles (IEX, DownloadString, Invoke-WebRequest)
  4. Defense evasion (AMSI bypass, Defender disable, log clearing)
  5. Reconnaissance commands (AD enumeration, network scanning)
  6. Persistence setup (scheduled tasks, registry, WMI)

History file: %APPDATA%\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt
No admin required - reads current user's history.

MITRE ATT&CK: T1059.001 (PowerShell)
"""

import os
import re
from datetime import datetime
from typing import List, Tuple

from scanner_core.utils import (
    Finding, RiskLevel,
    print_section, print_finding,
)


# ============================================================================
# Suspicious PowerShell command patterns
# Format: (regex, description, risk_level, mitre_id, always_report)
#   always_report=True  -> Report even a single occurrence
#   always_report=False -> Only report if combined with other indicators
# ============================================================================
SUSPICIOUS_PATTERNS = [
    # ---- CRITICAL: Known attack tools & commands ----
    (r"invoke-mimikatz", "Invoke-Mimikatz (credential dumping)", RiskLevel.CRITICAL, "T1003.001", True),
    (r"mimikatz", "Mimikatz reference", RiskLevel.CRITICAL, "T1003.001", True),
    (r"sekurlsa", "Sekurlsa credential access", RiskLevel.CRITICAL, "T1003.001", True),
    (r"invoke-kerberoast", "Kerberoasting attack", RiskLevel.CRITICAL, "T1558.003", True),
    (r"invoke-rubeus", "Rubeus Kerberos attack", RiskLevel.CRITICAL, "T1558", True),
    (r"invoke-bloodhound", "BloodHound AD enumeration", RiskLevel.HIGH, "T1087.002", True),
    (r"invoke-sharphound", "SharpHound AD collector", RiskLevel.HIGH, "T1087.002", True),
    (r"invoke-powershelltcp", "PowerShell TCP reverse shell", RiskLevel.CRITICAL, "T1059.001", True),
    (r"invoke-shellcode", "Shellcode injection", RiskLevel.CRITICAL, "T1055", True),
    (r"invoke-dllinjection", "DLL injection", RiskLevel.CRITICAL, "T1055.001", True),
    (r"invoke-reflectivepeinjection", "Reflective PE injection", RiskLevel.CRITICAL, "T1055.001", True),
    (r"invoke-tokenmanipulation", "Token manipulation", RiskLevel.CRITICAL, "T1134", True),
    (r"invoke-credentialinjection", "Credential injection", RiskLevel.CRITICAL, "T1055", True),
    (r"invoke-smbexec", "SMB remote execution", RiskLevel.CRITICAL, "T1021.002", True),
    (r"invoke-wmiexec", "WMI remote execution", RiskLevel.CRITICAL, "T1047", True),
    (r"invoke-psexec", "PsExec via PowerShell", RiskLevel.HIGH, "T1569.002", True),
    (r"invoke-thehash", "Pass-the-hash attack", RiskLevel.CRITICAL, "T1550.002", True),
    (r"invoke-smbclient", "SMB client (lateral movement)", RiskLevel.HIGH, "T1021.002", True),

    # ---- HIGH: Credential access ----
    (r"get-credential|convertto-securestring.*-asplaintext", "Credential handling", RiskLevel.MEDIUM, "T1059.001", False),
    (r"lsass.*dump|dump.*lsass", "LSASS dump attempt", RiskLevel.CRITICAL, "T1003.001", True),
    (r"sam.*dump|dump.*sam", "SAM dump attempt", RiskLevel.CRITICAL, "T1003.002", True),
    (r"ntds.*dit|dit.*ntds", "NTDS.dit extraction", RiskLevel.CRITICAL, "T1003.003", True),
    (r"dcsync|invoke-dcsync", "DCSync attack", RiskLevel.CRITICAL, "T1003.006", True),
    (r"hashdump|invoke-hashdump", "Password hash dumping", RiskLevel.CRITICAL, "T1003", True),

    # ---- HIGH: Download cradles ----
    (r"invoke-expression.*downloadstring", "IEX + DownloadString combo (download cradle)", RiskLevel.HIGH, "T1059.001", True),
    (r"\(new-object.*webclient\)\.download", "WebClient download cradle", RiskLevel.HIGH, "T1105", True),
    (r"invoke-webrequest.*-outfile", "Invoke-WebRequest download to file", RiskLevel.MEDIUM, "T1105", False),
    (r"start-bitstransfer", "BITS download transfer", RiskLevel.MEDIUM, "T1197", False),
    (r"certutil.*-urlcache", "Certutil download", RiskLevel.HIGH, "T1105", True),
    (r"bitsadmin.*\/transfer", "BitsAdmin download", RiskLevel.HIGH, "T1197", True),

    # ---- HIGH: Encoded/obfuscated commands ----
    (r"-enc(oded)?(c(ommand)?)?[\s]+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell command (long)", RiskLevel.HIGH, "T1059.001", True),
    (r"\[convert\]::frombase64string", "Base64 decoding", RiskLevel.HIGH, "T1140", True),
    (r"\[system\.text\.encoding\]::utf8\.getstring\(\[convert\]::frombase64", "Base64 decode + execute", RiskLevel.HIGH, "T1140", True),
    (r"iex.*\[system\.text", "IEX with encoding manipulation", RiskLevel.HIGH, "T1059.001", True),

    # ---- HIGH: Defense evasion ----
    (r"set-mppreference.*-disablerealtimemonitoring\s+\$true", "Disable Defender real-time", RiskLevel.CRITICAL, "T1562.001", True),
    (r"set-mppreference.*-disablebehaviormonitoring\s+\$true", "Disable Defender behavior monitoring", RiskLevel.CRITICAL, "T1562.001", True),
    (r"add-mppreference.*-exclusionpath", "Add Defender exclusion", RiskLevel.HIGH, "T1562.001", True),
    (r"add-mppreference.*-exclusionprocess", "Add Defender process exclusion", RiskLevel.HIGH, "T1562.001", True),
    (r"\[ref\]\.assembly.*amsiutils", "AMSI bypass attempt", RiskLevel.CRITICAL, "T1562.001", True),
    (r"amsiinitialized|amsiscanbuffer|amsi\.dll", "AMSI bypass technique", RiskLevel.CRITICAL, "T1562.001", True),
    (r"clear-eventlog|wevtutil\s+(cl|clear)", "Event log clearing", RiskLevel.HIGH, "T1070.001", True),
    (r"remove-item.*\\\$recycle", "Recycle bin manipulation", RiskLevel.MEDIUM, "T1070.004", False),
    (r"set-executionpolicy\s+(bypass|unrestricted)", "Execution policy bypass", RiskLevel.MEDIUM, "T1059.001", False),

    # ---- MEDIUM: Reconnaissance ----
    (r"get-aduser|get-adcomputer|get-adgroup|get-addomain", "Active Directory enumeration", RiskLevel.MEDIUM, "T1087.002", False),
    (r"get-netuser|get-netcomputer|get-netgroup|get-netdomain", "PowerView AD enumeration", RiskLevel.HIGH, "T1087.002", True),
    (r"get-domaincontroller|get-forest|get-domaintrust", "AD domain trust enumeration", RiskLevel.HIGH, "T1482", True),
    (r"test-connection.*-count\s+\d{3,}|1\.\.255.*test-connection", "Network sweep/ping scan", RiskLevel.MEDIUM, "T1018", False),
    (r"resolve-dnsname.*\|.*foreach", "DNS enumeration loop", RiskLevel.MEDIUM, "T1018", False),

    # ---- MEDIUM: Persistence ----
    (r"new-scheduledtask|register-scheduledtask|schtasks\s+/create", "Scheduled task creation", RiskLevel.MEDIUM, "T1053.005", False),
    (r"new-itemproperty.*\\\\run\\b|set-itemproperty.*\\\\run\\b", "Registry Run key modification", RiskLevel.HIGH, "T1547.001", True),
    (r"register-wmievent|set-wminstance", "WMI event subscription", RiskLevel.HIGH, "T1546.003", True),
    (r"new-service|sc\.exe\s+create", "Service creation", RiskLevel.MEDIUM, "T1543.003", False),

    # ---- MEDIUM: Network ----
    (r"new-pssession|enter-pssession|invoke-command\s+-computername", "Remote PowerShell session", RiskLevel.MEDIUM, "T1021.006", False),
    (r"new-object.*net\.sockets\.tcpclient", "Raw TCP connection", RiskLevel.HIGH, "T1095", True),
    (r"new-object.*net\.sockets\.tcplistener", "TCP listener (possible backdoor)", RiskLevel.HIGH, "T1095", True),
]


def _get_history_files() -> List[str]:
    """Find all PSReadLine history files for the current user."""
    files = []

    # Standard location
    appdata = os.environ.get("APPDATA", "")
    if appdata:
        std_path = os.path.join(
            appdata, "Microsoft", "Windows", "PowerShell",
            "PSReadLine", "ConsoleHost_history.txt"
        )
        if os.path.isfile(std_path):
            files.append(std_path)

        # Also check for ISE history
        ise_path = os.path.join(
            appdata, "Microsoft", "Windows", "PowerShell",
            "PSReadLine", "Windows PowerShell ISE Host_history.txt"
        )
        if os.path.isfile(ise_path):
            files.append(ise_path)

        # VS Code integrated terminal history
        vscode_path = os.path.join(
            appdata, "Microsoft", "Windows", "PowerShell",
            "PSReadLine", "Visual Studio Code Host_history.txt"
        )
        if os.path.isfile(vscode_path):
            files.append(vscode_path)

    return files


def scan() -> List[Finding]:
    """Run the PowerShell history scanner and return findings."""
    print_section("POWERSHELL HISTORY SCANNER - PSReadLine Analysis")
    findings = []

    history_files = _get_history_files()
    if not history_files:
        print("  [!] No PowerShell history files found")
        return findings

    print(f"  [i] Found {len(history_files)} history file(s)")

    for hist_file in history_files:
        try:
            file_size = os.path.getsize(hist_file)
            print(f"  [i] Analyzing: {os.path.basename(hist_file)} ({file_size:,} bytes)")

            with open(hist_file, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            print(f"  [i] Total commands: {len(lines)}")

            # Track which patterns we've already reported (avoid duplicates)
            reported_patterns = set()

            for line_num, line in enumerate(lines, 1):
                line_stripped = line.strip()
                if not line_stripped:
                    continue

                line_lower = line_stripped.lower()

                for pattern, desc, risk, mitre, always_flag in SUSPICIOUS_PATTERNS:
                    if re.search(pattern, line_lower):
                        # Deduplicate: only report each pattern type once per file
                        pattern_key = f"{pattern}:{hist_file}"
                        if pattern_key in reported_patterns:
                            # Count additional occurrences silently
                            continue

                        if not always_flag:
                            # For lower-confidence patterns, need additional context
                            # Skip if it's just a simple Get-ADUser or similar
                            pass

                        reported_patterns.add(pattern_key)

                        # Truncate command for display (may contain sensitive data)
                        display_cmd = line_stripped[:200]
                        if len(line_stripped) > 200:
                            display_cmd += "..."

                        finding = Finding(
                            module="PowerShell History Scanner",
                            risk=risk,
                            title=f"Suspicious PS command: {desc}",
                            description=f"PowerShell history contains a command matching: {desc}. "
                                        "This may indicate attacker activity or security testing.",
                            details={
                                "command": display_cmd,
                                "line_number": line_num,
                                "history_file": hist_file,
                                "pattern": desc,
                                "total_commands": len(lines),
                            },
                            mitre_id=mitre,
                            remediation=f"Review the command in context. If unauthorized, investigate the system. "
                                        f"History file: {hist_file}",
                        )
                        findings.append(finding)
                        print_finding(finding)
                        break  # Only match first pattern per line

        except (PermissionError, OSError) as e:
            print(f"  [!] Cannot read history file: {e}")

    print(f"  [i] PowerShell history scan complete. {len(findings)} findings.")
    return findings
