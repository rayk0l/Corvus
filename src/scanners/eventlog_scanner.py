"""
eventlog_scanner.py - Windows Event Log scanner module.
Context-aware: analyzes event CONTENT before alerting. Distinguishes
between legitimate IDE/OS scripts and actual attacks. No more flagging
VS Code/Cursor PowerShell profiles as malicious.
"""

import os
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import List
from collections import defaultdict

from scanner_core.utils import Finding, RiskLevel, print_section, print_finding

# Maximum events to retrieve per log (safety limit)
MAX_EVENTS = 2000

# Time window for log analysis (7 days in milliseconds)
TIME_WINDOW_MS = 7 * 24 * 60 * 60 * 1000

# Known-safe PowerShell script content patterns (if ANY of these are found
# in the script block, skip it — these are legitimate IDE/OS scripts)
SAFE_PS_CONTENT = [
    "copyright (c) microsoft corporation",
    "copyright (c) 2015 microsoft corporation",
    "windows powershell profile",
    "vscodestate",
    "vscode_",
    "cursor_",
    "antigravity",
    "chocolatey",
    "oh-my-posh",
    "starship",
    "posh-git",
    "terminal icons",
    "psreadline",
    "az.accounts",
    "microsoft.powershell.utility",
    "microsoft.powershell.management",
    "microsoft.powershell.security",
    "conda initialize",
    "anaconda",
    "nvm use",
    "fnm env",
    "prompt function",
    "set-executionpolicy",
    "import-module",
]


def _query_event_log(log_name: str, event_ids: List[int], max_events: int = MAX_EVENTS) -> List[dict]:
    """Query Windows Event Log using wevtutil."""
    events = []
    id_filter = " or ".join([f"EventID={eid}" for eid in event_ids])
    query = f"*[System[({id_filter}) and TimeCreated[timediff(@SystemTime) <= {TIME_WINDOW_MS}]]]"

    try:
        result = subprocess.run(
            ["wevtutil", "qe", log_name, "/q:" + query,
             "/f:xml", f"/c:{max_events}", "/rd:true"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace"
        )
        output = result.stdout.strip()
        if not output:
            return events

        xml_content = f"<Events>{output}</Events>"
        try:
            root = ET.fromstring(xml_content)
            ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}

            for event in root.findall(".//e:Event", ns):
                evt = {}
                system = event.find("e:System", ns)
                if system is not None:
                    eid_el = system.find("e:EventID", ns)
                    evt["EventID"] = int(eid_el.text) if eid_el is not None and eid_el.text else 0
                    time_el = system.find("e:TimeCreated", ns)
                    evt["TimeCreated"] = time_el.get("SystemTime", "") if time_el is not None else ""
                    comp_el = system.find("e:Computer", ns)
                    evt["Computer"] = comp_el.text if comp_el is not None else ""

                event_data = event.find("e:EventData", ns)
                if event_data is not None:
                    for data in event_data.findall("e:Data", ns):
                        name = data.get("Name", "")
                        value = data.text or ""
                        if name:
                            evt[name] = value

                events.append(evt)
        except ET.ParseError:
            pass

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return events


def _is_safe_ps_script(script_block: str) -> bool:
    """Check if a PowerShell script block is from a known-safe source."""
    script_lower = script_block.lower()
    for safe_pattern in SAFE_PS_CONTENT:
        if safe_pattern in script_lower:
            return True
    return False


def _scan_security_log() -> List[Finding]:
    """Scan Security event log for suspicious events."""
    findings = []

    # ---- Brute Force Detection (Event ID 4625) ----
    print("  [i] Checking for brute force attempts (4625)...")
    failed_logins = _query_event_log("Security", [4625], max_events=500)

    if len(failed_logins) >= 10:
        account_failures = defaultdict(int)
        source_ips = defaultdict(set)
        for evt in failed_logins:
            account = evt.get("TargetUserName", "Unknown")
            source = evt.get("IpAddress", "")
            account_failures[account] += 1
            if source and source != "-":
                source_ips[account].add(source)

        for account, count in account_failures.items():
            if count >= 10:
                finding = Finding(
                    module="Event Log Scanner",
                    risk=RiskLevel.HIGH,
                    title=f"Brute force detected: {count} failed logins for '{account}'",
                    description=f"{count} failed login attempts in the last 7 days.",
                    details={
                        "account": account,
                        "failed_attempts": count,
                        "source_ips": ", ".join(list(source_ips[account])[:10]),
                        "event_id": 4625,
                    },
                    mitre_id="T1110",
                    remediation="Block source IPs in the firewall. Enable account lockout policy: net accounts /lockoutthreshold:5",
                )
                findings.append(finding)
                print_finding(finding)

    # ---- New User Account Created (Event ID 4720) ----
    print("  [i] Checking for new user accounts (4720)...")
    new_accounts = _query_event_log("Security", [4720], max_events=50)
    for evt in new_accounts:
        target = evt.get("TargetUserName", "Unknown")
        creator = evt.get("SubjectUserName", "Unknown")
        finding = Finding(
            module="Event Log Scanner",
            risk=RiskLevel.MEDIUM,
            title=f"New user account created: {target}",
            description=f"Account '{target}' was created by '{creator}'.",
            details={
                "new_account": target,
                "created_by": creator,
                "time": evt.get("TimeCreated", ""),
                "event_id": 4720,
            },
            mitre_id="T1136.001",
            remediation=f"Verify account '{target}' was intentionally created. Disable if unauthorized: net user {target} /active:no",
        )
        findings.append(finding)
        print_finding(finding)

    # ---- Admin Group Change (Event ID 4732) ----
    print("  [i] Checking for admin group changes (4732)...")
    group_changes = _query_event_log("Security", [4732], max_events=50)
    for evt in group_changes:
        member = evt.get("MemberName", evt.get("MemberSid", "Unknown"))
        group = evt.get("TargetUserName", "Unknown")
        if "admin" in group.lower():
            finding = Finding(
                module="Event Log Scanner",
                risk=RiskLevel.HIGH,
                title=f"Member added to admin group: {group}",
                description=f"'{member}' was added to the '{group}' group.",
                details={
                    "member": member,
                    "group": group,
                    "added_by": evt.get("SubjectUserName", "Unknown"),
                    "time": evt.get("TimeCreated", ""),
                    "event_id": 4732,
                },
                mitre_id="T1098",
                remediation=f"Verify the group change was authorized. Remove if unauthorized: net localgroup {group} {member} /delete",
            )
            findings.append(finding)
            print_finding(finding)

    return findings


def _scan_system_log() -> List[Finding]:
    """Scan System event log for suspicious events."""
    findings = []

    # ---- New Service Installed (Event ID 7045) ----
    print("  [i] Checking for newly installed services (7045)...")
    new_services = _query_event_log("System", [7045], max_events=100)

    # Only flag services with MULTIPLE suspicious indicators
    suspicious_patterns = [
        r"-enc\s+[A-Za-z0-9+/=]{10,}",  # Encoded command (must have actual payload)
        r"frombase64.*downloadstring",     # Decode + download → strong indicator
        r"downloadstring.*frombase64",     # Same reversed
        r"invoke-expression.*download",    # IEX + download
        r"bitsadmin\s+/transfer",          # BITS download
        r"certutil\s+-urlcache",           # Certutil download
        r"mshta\s+http",                   # MSHTA remote
        r"mshta\s+javascript",             # MSHTA script
        r"regsvr32\s+/s\s+/n\s+/u",       # Regsvr32 bypass
    ]

    for evt in new_services:
        service_name = evt.get("ServiceName", evt.get("param1", "Unknown"))
        image_path = evt.get("ImagePath", evt.get("param2", ""))

        is_suspicious = any(
            re.search(p, image_path.lower()) for p in suspicious_patterns
        )
        if is_suspicious:
            finding = Finding(
                module="Event Log Scanner",
                risk=RiskLevel.HIGH,
                title=f"Suspicious service installed: {service_name}",
                description="A new service with attack-pattern command line was installed.",
                details={
                    "service_name": service_name,
                    "image_path": image_path[:500],
                    "time": evt.get("TimeCreated", ""),
                    "event_id": 7045,
                },
                mitre_id="T1543.003",
                remediation=f"Remove the suspicious service: sc delete \"{service_name}\". Investigate the source.",
            )
            findings.append(finding)
            print_finding(finding)

    # ---- Audit Log Cleared (Event ID 1102 + 104) ----
    print("  [i] Checking for log clearing events (1102, 104)...")
    log_clears = _query_event_log("Security", [1102], max_events=10)
    log_clears.extend(_query_event_log("System", [104], max_events=10))

    for evt in log_clears:
        finding = Finding(
            module="Event Log Scanner",
            risk=RiskLevel.CRITICAL,
            title="Security/audit log was cleared",
            description="Event logs were cleared — strong indicator of anti-forensics activity.",
            details={
                "cleared_by": evt.get("SubjectUserName", "Unknown"),
                "time": evt.get("TimeCreated", ""),
                "event_id": evt.get("EventID", ""),
            },
            mitre_id="T1070.001",
            remediation="Investigate who cleared the logs. Check for ongoing compromise. Enable centralized log forwarding.",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _scan_powershell_log() -> List[Finding]:
    """Scan PowerShell operational log with CONTEXT-AWARE analysis.
    Only flags scripts that contain attack patterns AND are NOT from known-safe sources."""
    findings = []

    print("  [i] Checking PowerShell script block logs (4104)...")
    ps_events = _query_event_log(
        "Microsoft-Windows-PowerShell/Operational", [4104], max_events=200
    )

    # These patterns require BOTH the pattern AND absence of safe content
    suspicious_ps_patterns = [
        # CRITICAL: Credential dumping / defense evasion — always flag
        # (pattern, label, risk, always_flag, mitre_id)
        (r"mimikatz", "Mimikatz reference", RiskLevel.CRITICAL, True, "T1003.001"),
        (r"invoke-mimikatz", "Invoke-Mimikatz", RiskLevel.CRITICAL, True, "T1003.001"),
        (r"sekurlsa", "Credential dumping (sekurlsa)", RiskLevel.CRITICAL, True, "T1003.001"),
        (r"invoke-shellcode", "Shellcode injection", RiskLevel.CRITICAL, True, "T1055"),
        (r"set-mppreference.*-disablerealtimemonitoring\s+\$true", "Defender disable", RiskLevel.CRITICAL, True, "T1562.001"),

        # HIGH: Suspicious download + exec combos (require multi-pattern)
        (r"invoke-expression.*downloadstring", "IEX + DownloadString combo", RiskLevel.HIGH, True, "T1059.001"),
        (r"downloadstring.*invoke-expression", "DownloadString + IEX combo", RiskLevel.HIGH, True, "T1059.001"),
        (r"-enc\s+[A-Za-z0-9+/=]{50,}", "Long encoded PowerShell (>50 chars)", RiskLevel.HIGH, True, "T1059.001"),
        (r"add-mppreference.*-exclusionpath", "Defender exclusion path", RiskLevel.HIGH, False, "T1562.001"),

        # MEDIUM: Need safe-content filter (can be in IDE profiles)
        (r"invoke-webrequest.*-outfile", "Web download to file", RiskLevel.MEDIUM, False, "T1105"),
        (r"start-bitstransfer", "BITS download", RiskLevel.MEDIUM, False, "T1197"),
        (r"net\.webclient.*download", "WebClient download", RiskLevel.MEDIUM, False, "T1105"),
    ]

    reported_scripts = set()

    for evt in ps_events:
        script_block = evt.get("ScriptBlockText", evt.get("param2", ""))
        if not script_block or len(script_block) < 30:
            continue

        script_hash = hash(script_block[:300])
        if script_hash in reported_scripts:
            continue

        # ---- CONTEXT CHECK: Skip known-safe IDE/OS scripts ----
        is_safe = _is_safe_ps_script(script_block)

        for pattern, label, risk, always_flag, mitre in suspicious_ps_patterns:
            if re.search(pattern, script_block, re.IGNORECASE):
                # If not always_flag AND script is from a safe source → skip
                if not always_flag and is_safe:
                    continue

                reported_scripts.add(script_hash)
                finding = Finding(
                    module="Event Log Scanner",
                    risk=risk,
                    title=f"Suspicious PowerShell: {label}",
                    description=f"PowerShell script block contains attack pattern: {label}",
                    details={
                        "pattern": label,
                        "script_preview": script_block[:500],
                        "time": evt.get("TimeCreated", ""),
                        "event_id": 4104,
                    },
                    mitre_id=mitre,
                    remediation="Investigate the PowerShell script source. Block execution if malicious.",
                )
                findings.append(finding)
                print_finding(finding)
                break

    return findings


def scan() -> List[Finding]:
    """Run the event log scanner and return findings."""
    print_section("EVENT LOG SCANNER - Context-Aware Security Event Analysis")
    findings = []

    print("  [i] Scanning Security event log...")
    findings.extend(_scan_security_log())

    print("  [i] Scanning System event log...")
    findings.extend(_scan_system_log())

    print("  [i] Scanning PowerShell event log...")
    findings.extend(_scan_powershell_log())

    print(f"  [i] Event log scan complete. {len(findings)} findings.")
    return findings
