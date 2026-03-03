"""
amcache_scanner.py - Execution history forensics module.
Analyzes Windows execution artifacts to detect previously run malicious tools:
  1. ShimCache (AppCompatCache) - Records every executable the OS checked
  2. UserAssist - Records GUI programs launched by the user (ROT13 encoded)
  3. BAM/DAM (Background Activity Moderator) - Recent execution evidence
  4. MUICache - Executable description cache

These artifacts persist even after the malicious file is deleted.

MITRE ATT&CK: T1059 (Command and Scripting Interpreter)
"""

import os
import re
import codecs
import winreg
import struct
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict, Set

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    print_section, print_finding,
)


# ============================================================================
# Known malicious / hacking tool names (partial match, lowercase)
# ============================================================================
MALICIOUS_TOOL_NAMES = {
    # Credential dumping
    "mimikatz": ("Mimikatz credential dumper", RiskLevel.CRITICAL, "T1003.001"),
    "lazagne": ("LaZagne credential harvester", RiskLevel.CRITICAL, "T1003"),
    "rubeus": ("Rubeus Kerberos attack tool", RiskLevel.CRITICAL, "T1558"),
    "safetykatz": ("SafetyKatz credential dumper", RiskLevel.CRITICAL, "T1003.001"),
    "sharpkatz": ("SharpKatz credential dumper", RiskLevel.CRITICAL, "T1003.001"),
    "pypykatz": ("Pypykatz credential dumper", RiskLevel.CRITICAL, "T1003.001"),
    "procdump": ("ProcDump (possible LSASS dump)", RiskLevel.HIGH, "T1003.001"),
    "nanodump": ("NanoDump LSASS dumper", RiskLevel.CRITICAL, "T1003.001"),

    # C2 / RAT
    "cobaltstrike": ("Cobalt Strike C2", RiskLevel.CRITICAL, "T1071.001"),
    "beacon": ("Cobalt Strike Beacon", RiskLevel.CRITICAL, "T1071.001"),
    "meterpreter": ("Metasploit Meterpreter", RiskLevel.CRITICAL, "T1071.001"),
    "empire": ("Empire C2 framework", RiskLevel.CRITICAL, "T1071.001"),
    "covenant": ("Covenant C2 framework", RiskLevel.CRITICAL, "T1071.001"),
    "sliver": ("Sliver C2 implant", RiskLevel.CRITICAL, "T1071.001"),
    "poshc2": ("PoshC2 framework", RiskLevel.CRITICAL, "T1071.001"),
    "bruteratel": ("Brute Ratel C4", RiskLevel.CRITICAL, "T1071.001"),

    # Lateral movement
    "psexec": ("PsExec remote execution", RiskLevel.HIGH, "T1569.002"),
    "wmiexec": ("WMI remote execution", RiskLevel.HIGH, "T1047"),
    "smbexec": ("SMB remote execution", RiskLevel.HIGH, "T1021.002"),
    "atexec": ("AT remote execution", RiskLevel.HIGH, "T1053.002"),
    "dcomexec": ("DCOM remote execution", RiskLevel.HIGH, "T1021.003"),
    "crackmapexec": ("CrackMapExec attack tool", RiskLevel.CRITICAL, "T1021.002"),
    "sharphound": ("BloodHound collector", RiskLevel.HIGH, "T1087"),
    "bloodhound": ("BloodHound AD recon", RiskLevel.HIGH, "T1087"),

    # Exploitation
    "metasploit": ("Metasploit framework", RiskLevel.CRITICAL, "T1203"),
    "exploit": ("Possible exploit tool", RiskLevel.MEDIUM, "T1203"),
    "eternal": ("EternalBlue/Romance exploit", RiskLevel.CRITICAL, "T1210"),
    "printspoofer": ("PrintSpoofer privilege escalation", RiskLevel.CRITICAL, "T1068"),
    "juicypotato": ("JuicyPotato privilege escalation", RiskLevel.CRITICAL, "T1068"),
    "sweetpotato": ("SweetPotato privilege escalation", RiskLevel.CRITICAL, "T1068"),
    "godpotato": ("GodPotato privilege escalation", RiskLevel.CRITICAL, "T1068"),
    "roguepotato": ("RoguePotato privilege escalation", RiskLevel.CRITICAL, "T1068"),

    # Recon / Enumeration
    "nmap": ("Nmap network scanner", RiskLevel.INFO, "T1046"),
    "masscan": ("Masscan port scanner", RiskLevel.INFO, "T1046"),
    "seatbelt": ("Seatbelt enumeration", RiskLevel.HIGH, "T1082"),
    "winpeas": ("WinPEAS privilege escalation", RiskLevel.HIGH, "T1082"),
    "linpeas": ("LinPEAS privilege escalation", RiskLevel.HIGH, "T1082"),
    "powerup": ("PowerUp privilege escalation", RiskLevel.HIGH, "T1082"),
    "adrecon": ("ADRecon Active Directory recon", RiskLevel.HIGH, "T1087.002"),

    # Tunneling / Proxy
    "chisel": ("Chisel tunnel proxy", RiskLevel.HIGH, "T1572"),
    "ligolo": ("Ligolo tunnel proxy", RiskLevel.HIGH, "T1572"),
    "plink": ("PuTTY Link (SSH tunnel)", RiskLevel.MEDIUM, "T1572"),
    "ngrok": ("Ngrok reverse tunnel", RiskLevel.MEDIUM, "T1572"),
    "frp": ("Fast Reverse Proxy", RiskLevel.HIGH, "T1572"),

    # Misc attack tools
    "hashcat": ("Hashcat password cracker", RiskLevel.HIGH, "T1110.002"),
    "johntheripper": ("John the Ripper cracker", RiskLevel.HIGH, "T1110.002"),
    "hydra": ("Hydra brute forcer", RiskLevel.HIGH, "T1110"),
    "impacket": ("Impacket attack suite", RiskLevel.CRITICAL, "T1021.002"),
    "responder": ("Responder LLMNR poisoner", RiskLevel.CRITICAL, "T1557.001"),
    "inveigh": ("Inveigh LLMNR/NBNS poisoner", RiskLevel.CRITICAL, "T1557.001"),
    "kerbrute": ("Kerbrute Kerberos brute force", RiskLevel.HIGH, "T1110"),
    "powerview": ("PowerView AD enumeration", RiskLevel.HIGH, "T1087.002"),
    "sharpsploit": ("SharpSploit attack library", RiskLevel.CRITICAL, "T1059"),
    "sharpup": ("SharpUp privilege escalation", RiskLevel.HIGH, "T1082"),
    "certify": ("Certify AD CS abuse", RiskLevel.HIGH, "T1649"),
    "whisker": ("Whisker shadow credential", RiskLevel.CRITICAL, "T1556"),
}

# Safe tool names to exclude from UserAssist/MUI to reduce false positives
SAFE_PARTIAL_MATCHES = {
    "explorer", "chrome", "firefox", "edge", "notepad", "calc",
    "paint", "wordpad", "cmd", "powershell", "regedit", "taskmgr",
    "devenv", "code", "cursor", "idea", "pycharm", "webstorm",
    "spotify", "discord", "steam", "teams", "slack", "zoom",
    "winrar", "7z", "vlc", "acrobat", "python", "node", "git",
    "docker", "everything",
}


def _check_tool_name(name: str) -> tuple:
    """Check if a name matches known malicious tools. Returns (desc, risk, mitre) or None."""
    name_lower = name.lower()

    # Skip safe tools
    for safe in SAFE_PARTIAL_MATCHES:
        if safe in name_lower:
            return None

    for tool_key, (desc, risk, mitre) in MALICIOUS_TOOL_NAMES.items():
        if tool_key in name_lower:
            return (desc, risk, mitre)

    return None


def _scan_userassist() -> List[Finding]:
    """
    Scan UserAssist registry keys for evidence of malicious GUI programs.
    UserAssist entries are ROT13-encoded program paths.
    """
    findings = []
    userassist_paths = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\UserAssist",
    ]

    for ua_base in userassist_paths:
        try:
            base_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_base)
            # Enumerate GUID subkeys
            i = 0
            while True:
                try:
                    guid = winreg.EnumKey(base_key, i)
                    count_path = f"{ua_base}\\{guid}\\Count"
                    try:
                        count_key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path)
                        j = 0
                        while True:
                            try:
                                name, value, _ = winreg.EnumValue(count_key, j)
                                # Decode ROT13
                                decoded = codecs.decode(name, 'rot_13')
                                match = _check_tool_name(decoded)
                                if match:
                                    desc, risk, mitre = match
                                    finding = Finding(
                                        module="Amcache Scanner",
                                        risk=risk,
                                        title=f"Malicious tool in UserAssist: {os.path.basename(decoded)}",
                                        description=f"{desc}. Evidence found in UserAssist registry (GUI execution history).",
                                        details={
                                            "decoded_path": decoded,
                                            "source": "UserAssist (HKCU)",
                                            "evidence_type": "GUI program execution history",
                                            "note": "Tool was executed via GUI even if deleted",
                                        },
                                        mitre_id=mitre,
                                        remediation="Investigate the system for compromise. "
                                                    "The tool may still be present or was previously used.",
                                    )
                                    findings.append(finding)
                                    print_finding(finding)
                                j += 1
                            except OSError:
                                break
                        winreg.CloseKey(count_key)
                    except OSError:
                        pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(base_key)
        except OSError:
            pass

    return findings


def _scan_bam_dam() -> List[Finding]:
    """
    Scan BAM/DAM (Background Activity Moderator) for recent execution evidence.
    Available on Windows 10 1709+ and Windows 11.
    Registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings
    """
    findings = []
    bam_paths = [
        r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings",
        r"SYSTEM\CurrentControlSet\Services\bam\UserSettings",
        r"SYSTEM\CurrentControlSet\Services\dam\State\UserSettings",
        r"SYSTEM\CurrentControlSet\Services\dam\UserSettings",
    ]

    for bam_path in bam_paths:
        try:
            base_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, bam_path)
            # Enumerate SID subkeys
            i = 0
            while True:
                try:
                    sid = winreg.EnumKey(base_key, i)
                    sid_path = f"{bam_path}\\{sid}"
                    try:
                        sid_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, sid_path)
                        j = 0
                        while True:
                            try:
                                name, value, val_type = winreg.EnumValue(sid_key, j)
                                if name.startswith("\\"):
                                    # This is an executable path
                                    match = _check_tool_name(name)
                                    if match:
                                        desc, risk, mitre = match
                                        # Try to parse timestamp from value (FILETIME)
                                        timestamp = ""
                                        if isinstance(value, bytes) and len(value) >= 8:
                                            try:
                                                ft = struct.unpack('<Q', value[:8])[0]
                                                if ft > 0:
                                                    # Convert FILETIME to datetime
                                                    epoch = datetime(1601, 1, 1) + timedelta(microseconds=ft // 10)
                                                    timestamp = epoch.strftime("%Y-%m-%d %H:%M:%S")
                                            except (struct.error, OverflowError, ValueError):
                                                pass

                                        finding = Finding(
                                            module="Amcache Scanner",
                                            risk=risk,
                                            title=f"Malicious tool in BAM: {os.path.basename(name)}",
                                            description=f"{desc}. Evidence found in BAM/DAM registry (recent execution history).",
                                            details={
                                                "executable_path": name,
                                                "last_execution": timestamp or "Unknown",
                                                "sid": sid,
                                                "source": "BAM/DAM Registry",
                                                "evidence_type": "Background activity execution log",
                                            },
                                            mitre_id=mitre,
                                            remediation="Investigate the system immediately. Check if the tool "
                                                        "is still present on disk and perform malware analysis.",
                                        )
                                        findings.append(finding)
                                        print_finding(finding)
                                j += 1
                            except OSError:
                                break
                        winreg.CloseKey(sid_key)
                    except OSError:
                        pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(base_key)
        except OSError:
            pass

    return findings


def _scan_muicache() -> List[Finding]:
    """
    Scan MUICache for evidence of executed programs.
    MUI stores display names for executed executables.
    Registry entries have suffixes like .FriendlyAppName, .ApplicationCompany, etc.
    We deduplicate by base executable name to avoid duplicate findings.
    """
    findings = []
    reported_executables = set()  # Track reported exe names to avoid duplicates
    mui_paths = [
        r"SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache",
    ]

    # MUICache value name suffixes to strip for deduplication
    MUI_SUFFIXES = (
        ".friendlyappname", ".applicationcompany", ".applicationdescription",
        ".applicationicon", ".applicationname",
    )

    for mui_path in mui_paths:
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, mui_path)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)

                    # Extract base executable path by removing MUI suffixes
                    name_lower = name.lower()
                    base_name = name
                    for suffix in MUI_SUFFIXES:
                        if name_lower.endswith(suffix):
                            base_name = name[:len(name) - len(suffix)]
                            break

                    # Deduplicate: skip if we already reported this executable
                    base_key = base_name.lower()
                    if base_key in reported_executables:
                        i += 1
                        continue

                    match = _check_tool_name(base_name)
                    if match:
                        desc, risk, mitre = match
                        reported_executables.add(base_key)
                        exe_basename = os.path.basename(base_name)

                        finding = Finding(
                            module="Amcache Scanner",
                            risk=risk,
                            title=f"Malicious tool in MUICache: {exe_basename}",
                            description=f"{desc}. Evidence found in MUICache registry (execution history).",
                            details={
                                "registry_entry": base_name,
                                "display_name": str(value),
                                "source": "MUICache (HKCU)",
                                "evidence_type": "Program description cache",
                            },
                            mitre_id=mitre,
                            remediation="Investigate execution of this tool. "
                                        "MUICache evidence persists even after file deletion.",
                        )
                        findings.append(finding)
                        print_finding(finding)
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            pass

    return findings


def _scan_shimcache() -> List[Finding]:
    """
    Scan ShimCache (AppCompatCache) for execution artifacts.
    Uses reg export + parsing since direct binary parsing is complex.
    """
    findings = []

    try:
        # Use PowerShell to extract AppCompatCache entries
        ps_cmd = (
            "try { "
            "$key = Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache' -ErrorAction Stop; "
            "$data = $key.AppCompatCache; "
            "if ($data) { "
            "  # Extract readable strings from binary data "
            "  $text = [System.Text.Encoding]::Unicode.GetString($data); "
            "  $paths = [regex]::Matches($text, '[A-Z]:\\\\[^\\x00]+?\\.exe') | ForEach-Object { $_.Value }; "
            "  $paths | Select-Object -Unique | ForEach-Object { $_ } "
            "} "
            "} catch { Write-Output 'ERROR' }"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace"
        )

        if result.stdout.strip() and result.stdout.strip() != "ERROR":
            paths = result.stdout.strip().split("\n")
            for path in paths:
                path = path.strip()
                if not path:
                    continue
                match = _check_tool_name(path)
                if match:
                    desc, risk, mitre = match
                    finding = Finding(
                        module="Amcache Scanner",
                        risk=risk,
                        title=f"Malicious tool in ShimCache: {os.path.basename(path)}",
                        description=f"{desc}. Evidence found in ShimCache (AppCompatCache) - "
                                    "OS-level execution tracking.",
                        details={
                            "executable_path": path,
                            "source": "ShimCache (AppCompatCache)",
                            "evidence_type": "OS compatibility check history",
                            "note": "File was checked by the OS, strong evidence of execution attempt",
                        },
                        mitre_id=mitre,
                        remediation="This tool was present on the system. Investigate immediately. "
                                    "Check if the file still exists and perform incident response.",
                    )
                    findings.append(finding)
                    print_finding(finding)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return findings


def scan() -> List[Finding]:
    """Run the execution history scanner and return findings."""
    print_section("AMCACHE SCANNER - Execution History Forensics")
    findings = []

    # 1. UserAssist (current user, no admin needed)
    print("  [i] Scanning UserAssist (GUI execution history)...")
    ua_findings = _scan_userassist()
    findings.extend(ua_findings)
    print(f"  [i] UserAssist: {len(ua_findings)} findings")

    # 2. BAM/DAM (needs admin for HKLM, but try anyway)
    print("  [i] Scanning BAM/DAM (recent execution log)...")
    bam_findings = _scan_bam_dam()
    findings.extend(bam_findings)
    print(f"  [i] BAM/DAM: {len(bam_findings)} findings")

    # 3. MUICache (current user, no admin needed)
    print("  [i] Scanning MUICache (program description cache)...")
    mui_findings = _scan_muicache()
    findings.extend(mui_findings)
    print(f"  [i] MUICache: {len(mui_findings)} findings")

    # 4. ShimCache (needs admin for HKLM)
    print("  [i] Scanning ShimCache (AppCompatCache)...")
    shim_findings = _scan_shimcache()
    findings.extend(shim_findings)
    print(f"  [i] ShimCache: {len(shim_findings)} findings")

    print(f"  [i] Execution history scan complete. {len(findings)} findings.")
    return findings
