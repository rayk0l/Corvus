"""
prefetch_scanner.py - Windows Prefetch forensic analysis module.
Analyzes Prefetch files (.pf) to detect previously executed malicious tools.
Prefetch files are created by Windows for every executed program and persist
even after the original executable is deleted.

Requirements: Administrator privileges (Prefetch directory is protected)
Supported: Windows 7/8/10/11 (not Server by default)

MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
"""

import os
import re
import struct
from datetime import datetime, timedelta
from typing import List, Set

from scanner_core.utils import (
    Finding, RiskLevel,
    is_admin, print_section, print_finding,
)


# ============================================================================
# Known malicious tool prefetch names (lowercase, without hash suffix)
# Format: (pattern, description, risk_level, mitre_id)
# ============================================================================
MALICIOUS_PREFETCH_PATTERNS = [
    # Credential dumping
    (r"^mimikatz", "Mimikatz credential dumper", RiskLevel.CRITICAL, "T1003.001"),
    (r"^lazagne", "LaZagne credential harvester", RiskLevel.CRITICAL, "T1003"),
    (r"^rubeus", "Rubeus Kerberos attack tool", RiskLevel.CRITICAL, "T1558"),
    (r"^safetykatz", "SafetyKatz credential dumper", RiskLevel.CRITICAL, "T1003.001"),
    (r"^procdump.*\.exe", "ProcDump (potential LSASS dump)", RiskLevel.HIGH, "T1003.001"),
    (r"^nanodump", "NanoDump LSASS dumper", RiskLevel.CRITICAL, "T1003.001"),
    (r"^pypykatz", "Pypykatz credential dumper", RiskLevel.CRITICAL, "T1003.001"),

    # C2 / RAT
    (r"^beacon", "Cobalt Strike Beacon", RiskLevel.CRITICAL, "T1071.001"),
    (r"^cobaltstrike", "Cobalt Strike", RiskLevel.CRITICAL, "T1071.001"),

    # Lateral movement
    (r"^psexec", "PsExec remote execution", RiskLevel.HIGH, "T1569.002"),
    (r"^psexesvc", "PsExec service component", RiskLevel.HIGH, "T1569.002"),
    (r"^wmiexec", "WMI remote execution", RiskLevel.HIGH, "T1047"),
    (r"^smbexec", "SMB remote execution", RiskLevel.HIGH, "T1021.002"),
    (r"^crackmapexec", "CrackMapExec attack tool", RiskLevel.CRITICAL, "T1021.002"),
    (r"^sharphound", "BloodHound collector", RiskLevel.HIGH, "T1087"),

    # Exploitation
    (r"^printspoofer", "PrintSpoofer privilege escalation", RiskLevel.CRITICAL, "T1068"),
    (r"^juicypotato", "JuicyPotato privilege escalation", RiskLevel.CRITICAL, "T1068"),
    (r"^sweetpotato", "SweetPotato privilege escalation", RiskLevel.CRITICAL, "T1068"),
    (r"^godpotato", "GodPotato privilege escalation", RiskLevel.CRITICAL, "T1068"),
    (r"^roguepotato", "RoguePotato privilege escalation", RiskLevel.CRITICAL, "T1068"),

    # Recon
    (r"^nmap", "Nmap network scanner", RiskLevel.MEDIUM, "T1046"),
    (r"^masscan", "Masscan port scanner", RiskLevel.MEDIUM, "T1046"),
    (r"^seatbelt", "Seatbelt enumeration tool", RiskLevel.HIGH, "T1082"),
    (r"^winpeas", "WinPEAS privilege escalation scanner", RiskLevel.HIGH, "T1082"),
    (r"^powerup", "PowerUp priv esc tool", RiskLevel.HIGH, "T1082"),

    # Tunneling
    (r"^chisel", "Chisel tunnel proxy", RiskLevel.HIGH, "T1572"),
    (r"^ligolo", "Ligolo tunnel proxy", RiskLevel.HIGH, "T1572"),
    (r"^ngrok", "Ngrok reverse tunnel", RiskLevel.MEDIUM, "T1572"),

    # Password cracking
    (r"^hashcat", "Hashcat password cracker", RiskLevel.HIGH, "T1110.002"),

    # Network poisoning
    (r"^responder", "Responder LLMNR poisoner", RiskLevel.CRITICAL, "T1557.001"),
    (r"^inveigh", "Inveigh LLMNR/NBNS poisoner", RiskLevel.CRITICAL, "T1557.001"),

    # Misc
    (r"^impacket", "Impacket attack suite", RiskLevel.CRITICAL, "T1021.002"),
    (r"^certify", "Certify AD CS abuse tool", RiskLevel.HIGH, "T1649"),
    (r"^kerbrute", "Kerbrute Kerberos brute force", RiskLevel.HIGH, "T1110"),
    (r"^adrecon", "ADRecon Active Directory recon", RiskLevel.HIGH, "T1087.002"),
    (r"^sharpsploit", "SharpSploit attack library", RiskLevel.CRITICAL, "T1059"),

    # Suspicious generic patterns
    (r"^(rev|reverse).*shell", "Reverse shell tool", RiskLevel.CRITICAL, "T1059"),
    (r"^(nc|ncat|netcat)", "Netcat (network utility/backdoor)", RiskLevel.HIGH, "T1059"),
    (r"^(bind|back).*shell", "Bind/back shell tool", RiskLevel.CRITICAL, "T1059"),
]

# Known safe prefetch files to skip
SAFE_PREFETCH_PREFIXES = {
    "chrome", "firefox", "msedge", "explorer", "svchost", "csrss", "lsass",
    "services", "winlogon", "dwm", "taskhostw", "runtimebroker",
    "searchhost", "startmenuexperiencehost", "shellexperiencehost",
    "applicationframehost", "systemsettings", "sihost", "ctfmon",
    "conhost", "cmd", "powershell", "windowsterminal", "code",
    "cursor", "notepad", "mspaint", "calc", "devenv", "msbuild",
    "python", "node", "git", "docker", "java", "javaw",
    "setup", "install", "update", "updater", "unins", "msiexec",
    "dllhost", "wmiprvse", "taskmgr", "regedit", "mmc",
    "spotify", "discord", "slack", "teams", "zoom",
    "onedrive", "dropbox", "googledrivefsnotfound",
    "windowspackagemanager", "winget",
    "securityhealthservice", "msmpeng", "mpcmdrun",
    "backgroundtaskhost", "audiodg", "fontdrvhost",
    "searchindexer", "searchprotocolhost", "searchfilterhost",
    "spoolsv", "wuauclt", "trustedinstaller", "tiworker",
}


def _parse_prefetch_filename(pf_name: str) -> dict:
    """
    Parse a Prefetch filename.
    Format: EXECUTABLE_NAME-HASH.pf
    Example: CMD.EXE-4A81B364.pf -> {'exe_name': 'CMD.EXE', 'hash': '4A81B364'}
    """
    # Remove .pf extension
    name = pf_name[:-3] if pf_name.lower().endswith(".pf") else pf_name

    # Split at last dash (hash is always 8 hex chars)
    match = re.match(r'^(.+)-([0-9A-Fa-f]{8})$', name)
    if match:
        return {
            "exe_name": match.group(1),
            "hash": match.group(2),
        }
    return {"exe_name": name, "hash": ""}


def _get_file_times(filepath: str) -> dict:
    """Get file creation and modification times."""
    try:
        stat = os.stat(filepath)
        return {
            "created": datetime.fromtimestamp(stat.st_ctime).strftime("%Y-%m-%d %H:%M:%S"),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "accessed": datetime.fromtimestamp(stat.st_atime).strftime("%Y-%m-%d %H:%M:%S"),
        }
    except OSError:
        return {"created": "Unknown", "modified": "Unknown", "accessed": "Unknown"}


def scan() -> List[Finding]:
    """Run the Prefetch scanner and return findings."""
    print_section("PREFETCH SCANNER - Execution History Analysis")
    findings = []

    prefetch_dir = os.path.join(
        os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch"
    )

    if not os.path.isdir(prefetch_dir):
        print("  [!] Prefetch directory not found (may be disabled)")
        return findings

    # Check access
    try:
        pf_files = [f for f in os.listdir(prefetch_dir) if f.lower().endswith(".pf")]
    except PermissionError:
        if not is_admin():
            print("  [!] Prefetch directory requires Administrator privileges")
            print("      Tip: Run as Administrator for full Prefetch analysis")
        else:
            print("  [!] Cannot access Prefetch directory")
        return findings

    print(f"  [i] Found {len(pf_files)} Prefetch files")

    if not pf_files:
        print("  [i] No Prefetch files found (Prefetch may be disabled)")
        return findings

    reported = set()

    for pf_file in pf_files:
        parsed = _parse_prefetch_filename(pf_file)
        exe_name = parsed["exe_name"]
        exe_lower = exe_name.lower()

        # Skip known safe
        if any(exe_lower.startswith(safe) for safe in SAFE_PREFETCH_PREFIXES):
            continue

        # Skip already reported (same exe, different hash)
        if exe_lower in reported:
            continue

        # Check against malicious patterns
        for pattern, desc, risk, mitre in MALICIOUS_PREFETCH_PATTERNS:
            if re.match(pattern, exe_lower):
                reported.add(exe_lower)

                pf_path = os.path.join(prefetch_dir, pf_file)
                times = _get_file_times(pf_path)

                # Check if the original exe still exists
                # (Prefetch filename doesn't contain full path, but times give context)

                finding = Finding(
                    module="Prefetch Scanner",
                    risk=risk,
                    title=f"Malicious tool in Prefetch: {exe_name}",
                    description=f"{desc}. Prefetch evidence proves this tool was executed on the system. "
                                "Prefetch files persist even after the executable is deleted.",
                    details={
                        "executable": exe_name,
                        "prefetch_file": pf_file,
                        "prefetch_hash": parsed["hash"],
                        "pf_created": times["created"],
                        "pf_modified": times["modified"],
                        "source": "Windows Prefetch",
                        "evidence_type": "Execution artifact (OS-level)",
                    },
                    mitre_id=mitre,
                    remediation=f"Investigate when and how '{exe_name}' was executed. "
                                f"Check Prefetch timestamps for execution timeline. "
                                f"Delete Prefetch file if confirmed malicious: del \"{pf_path}\"",
                )
                findings.append(finding)
                print_finding(finding)
                break

    # Also check for suspicious patterns: too many unique cmd/powershell prefetch files
    # (Different hashes = different working directories = possible enumeration)
    ps_prefetch = [f for f in pf_files if f.upper().startswith("POWERSHELL")]
    if len(ps_prefetch) > 5:
        finding = Finding(
            module="Prefetch Scanner",
            risk=RiskLevel.INFO,
            title=f"Multiple PowerShell Prefetch entries ({len(ps_prefetch)})",
            description="Multiple Prefetch files for PowerShell with different hashes may indicate "
                        "extensive scripting activity from different locations.",
            details={
                "count": len(ps_prefetch),
                "files": ", ".join(ps_prefetch[:10]),
                "source": "Windows Prefetch",
            },
            mitre_id="T1059.001",
            remediation="Review PowerShell usage. Check PowerShell logs for suspicious activity.",
        )
        findings.append(finding)
        print_finding(finding)

    print(f"  [i] Prefetch scan complete. {len(findings)} findings.")
    return findings
