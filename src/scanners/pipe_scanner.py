"""
pipe_scanner.py - Named Pipe scanner module.
Detects suspicious named pipes commonly used by:
  1. C2 frameworks (Cobalt Strike, Metasploit, PoshC2, Covenant, Sliver)
  2. Lateral movement tools (PsExec, WMI, WinRM)
  3. Credential dumping tools (Mimikatz, Rubeus)
  4. Implant/beacon communication channels

MITRE ATT&CK: T1570 (Lateral Tool Transfer), T1021.002 (SMB/Windows Admin Shares)
"""

import os
import re
import subprocess
from typing import List, Set

from scanner_core.utils import (
    Finding, RiskLevel,
    print_section, print_finding,
)


# ============================================================================
# Known malicious / C2 named pipe patterns
# Format: (regex_pattern, description, risk_level, mitre_id)
# ============================================================================
MALICIOUS_PIPE_PATTERNS = [
    # ---- Cobalt Strike ----
    (r"^msagent_[0-9a-f]+$", "Cobalt Strike default pipe (msagent_*)", RiskLevel.CRITICAL, "T1071.001"),
    (r"^MSSE-[0-9]+-server$", "Cobalt Strike SMB beacon (MSSE-*-server)", RiskLevel.CRITICAL, "T1071.001"),
    (r"^postex_[0-9a-f]+$", "Cobalt Strike post-exploitation pipe", RiskLevel.CRITICAL, "T1071.001"),
    (r"^postex_ssh_[0-9a-f]+$", "Cobalt Strike SSH pipe", RiskLevel.CRITICAL, "T1071.001"),
    (r"^status_[0-9a-f]+$", "Cobalt Strike status pipe", RiskLevel.CRITICAL, "T1071.001"),
    (r"^msagent_[0-9a-f]{2}$", "Cobalt Strike short pipe", RiskLevel.CRITICAL, "T1071.001"),
    (r"^win_svc_[0-9a-f]+$", "Cobalt Strike service pipe", RiskLevel.CRITICAL, "T1071.001"),
    (r"^ntsvcs_[0-9a-f]+$", "Cobalt Strike NTSVCS pipe", RiskLevel.CRITICAL, "T1071.001"),
    (r"^scerpc_[0-9a-f]+$", "Cobalt Strike SCERPC pipe", RiskLevel.CRITICAL, "T1071.001"),
    (r"^dce_[0-9a-f]+$", "Cobalt Strike DCE pipe", RiskLevel.CRITICAL, "T1071.001"),

    # ---- Metasploit / Meterpreter ----
    (r"^meterpreter", "Metasploit Meterpreter pipe", RiskLevel.CRITICAL, "T1071.001"),
    (r"^rpc_[0-9a-f]{8}$", "Metasploit RPC pipe", RiskLevel.HIGH, "T1071.001"),

    # ---- PoshC2 ----
    (r"^PoshC2", "PoshC2 C2 framework pipe", RiskLevel.CRITICAL, "T1071.001"),

    # ---- Covenant ----
    (r"^gruntsvc", "Covenant C2 framework pipe", RiskLevel.CRITICAL, "T1071.001"),

    # ---- Sliver ----
    (r"^sliver", "Sliver C2 framework pipe", RiskLevel.CRITICAL, "T1071.001"),

    # ---- Mimikatz / Credential tools ----
    (r"^mimikatz", "Mimikatz credential dumping pipe", RiskLevel.CRITICAL, "T1003.001"),
    (r"^sekurlsa", "Sekurlsa credential dumping pipe", RiskLevel.CRITICAL, "T1003.001"),
    (r"^kerberos", "Potential Kerberoasting tool pipe", RiskLevel.HIGH, "T1558.003"),

    # ---- PsExec / Sysinternals ----
    (r"^PSEXESVC", "PsExec remote execution pipe", RiskLevel.HIGH, "T1569.002"),
    (r"^PSEXESVC-[0-9A-Z]+-[0-9]+-stdin$", "PsExec stdin pipe", RiskLevel.HIGH, "T1569.002"),
    (r"^PSEXESVC-[0-9A-Z]+-[0-9]+-stdout$", "PsExec stdout pipe", RiskLevel.HIGH, "T1569.002"),
    (r"^PSEXESVC-[0-9A-Z]+-[0-9]+-stderr$", "PsExec stderr pipe", RiskLevel.HIGH, "T1569.002"),
    (r"^RemCom_communicaton", "RemCom (PsExec alternative) pipe", RiskLevel.HIGH, "T1569.002"),

    # ---- Empire ----
    (r"^empire", "Empire C2 framework pipe", RiskLevel.CRITICAL, "T1071.001"),

    # ---- Generic suspicious patterns ----
    (r"^(shell|cmd|exec|beacon|implant|c2|payload|inject|reverse)_", "Suspicious C2-like pipe name", RiskLevel.HIGH, "T1570"),
    (r"^(backdoor|trojan|rat|hack)", "Suspicious malware-like pipe name", RiskLevel.HIGH, "T1570"),

    # ---- CrackMapExec ----
    (r"^cme_[0-9a-f]+$", "CrackMapExec pipe", RiskLevel.CRITICAL, "T1021.002"),

    # ---- Impacket ----
    (r"^impacket", "Impacket tool pipe", RiskLevel.CRITICAL, "T1021.002"),
    (r"^__eventlog$", "Impacket WMI pipe", RiskLevel.HIGH, "T1021.002"),

    # ---- PrintNightmare / PrintSpoofer ----
    (r"^spoolss_[0-9a-f]+$", "Potential PrintSpoofer exploit pipe", RiskLevel.HIGH, "T1068"),

    # ---- EfsPotato / Potato family ----
    (r"^efsrpc", "Potential EfsPotato privilege escalation pipe", RiskLevel.HIGH, "T1068"),
]

# Known safe pipes that Windows and common software create
SAFE_PIPE_PATTERNS = [
    # Windows built-in
    r"^(InitShutdown|lsass|ntsvcs|scerpc|wkssvc|srvsvc|svcctl|samr|netlogon|browser)$",
    r"^(winreg|epmapper|eventlog|spoolss|atsvc|protected_storage|plugplay)$",
    r"^(W32TIME_ALT|tapsrv|trkwks|ROUTER|DAV RPC SERVICE|MsFteWds)$",
    r"^(PIPE_EVENTROOT|LSM_API_service|vgauth-service|vmware-).*",
    # Security tools
    r"^(MsMpCom|PSHost\.|dotnet-diagnostic-|clr-debug-|ProtectedPrefix).*",
    r"^(Winsock2|RPC Control|TSAPI|LSARPC|NETLOGON|WMIEP_|OBJREF_).*",
    # Browsers
    r"^(chrome\.|chromium\.|mojo\.|crashpad_|firefox|gecko-).*",
    r"^(msedge\.).*",
    # Dev tools
    r"^(docker_engine|VBoxTray|vscode-|git-|npm-|yarn-).*",
    # SQL
    r"^(sql\\|MSSQL\$|SQLLocal\\).*",
    # Print
    r"^(PDF|print|cairo).*",
    # Windows internal
    r"^(TermSrv_API_service|Ctx_WinStation_API_service|thr_pipe_).*",
    r"^(AppContracts_|UIA_PIPE_|Winsock2\\CatalogChangeListener).*",
    r"^(PIPE_EVENTROOT\\CIMV2SCM EVENT PROVIDER)$",
    r"^(msedge\.nativeMessaging\.).*",
]


def _get_named_pipes() -> List[str]:
    """Enumerate all active named pipes on the system."""
    pipes = []

    # Method 1: List \\.\pipe\ directory
    pipe_dir = r"\\.\pipe"
    try:
        result = subprocess.run(
            ["cmd", "/c", f"dir /B {pipe_dir}"],
            capture_output=True, text=True, timeout=10,
            encoding="utf-8", errors="replace"
        )
        for line in result.stdout.strip().split("\n"):
            line = line.strip()
            if line:
                pipes.append(line)
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    # Method 2: PowerShell fallback if cmd didn't work
    if not pipes:
        try:
            ps_cmd = "[System.IO.Directory]::GetFiles('\\\\.\\pipe\\') | ForEach-Object { $_.Replace('\\\\.\\pipe\\', '') }"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace"
            )
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line:
                    pipes.append(line)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            pass

    return pipes


def _get_pipe_owner(pipe_name: str) -> str:
    """Try to determine the process that owns a named pipe."""
    try:
        # Use handle.exe from Sysinternals if available, otherwise try PowerShell
        ps_cmd = (
            f"Get-Process | ForEach-Object {{ "
            f"$p = $_; try {{ $p.Modules | Where-Object {{ $_.ModuleName }} }} catch {{}} "
            f"}} 2>$null | Select-Object -First 1"
        )
        # Simplified: just try to get pipe server process via Get-ChildItem
        ps_cmd = (
            f"try {{ "
            f"$pipe = [System.IO.Pipes.NamedPipeClientStream]::new('.', '{pipe_name}', 'Read'); "
            f"$pipe.Close(); 'accessible' "
            f"}} catch {{ 'restricted' }}"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=3,
            encoding="utf-8", errors="replace"
        )
        return result.stdout.strip()
    except Exception:
        return "unknown"


def _is_safe_pipe(pipe_name: str) -> bool:
    """Check if a pipe matches known safe patterns."""
    for pattern in SAFE_PIPE_PATTERNS:
        if re.match(pattern, pipe_name, re.IGNORECASE):
            return True
    return False


def scan() -> List[Finding]:
    """Run the named pipe scanner and return findings."""
    print_section("NAMED PIPE SCANNER - C2 & Lateral Movement Detection")
    findings = []

    print("  [i] Enumerating active named pipes...")
    pipes = _get_named_pipes()
    print(f"  [i] Found {len(pipes)} active named pipes")

    if not pipes:
        print("  [!] Could not enumerate named pipes (may need admin privileges)")
        return findings

    suspicious_count = 0

    for pipe_name in pipes:
        # Skip known safe pipes
        if _is_safe_pipe(pipe_name):
            continue

        # Check against malicious patterns
        for pattern, description, risk, mitre_id in MALICIOUS_PIPE_PATTERNS:
            if re.match(pattern, pipe_name, re.IGNORECASE):
                suspicious_count += 1
                finding = Finding(
                    module="Pipe Scanner",
                    risk=risk,
                    title=f"Malicious named pipe: {pipe_name}",
                    description=f"{description}. This named pipe is associated with known attack tools.",
                    details={
                        "pipe_name": pipe_name,
                        "pipe_path": f"\\\\.\\pipe\\{pipe_name}",
                        "pattern_matched": description,
                        "detection_rule": pattern,
                    },
                    mitre_id=mitre_id,
                    remediation=f"Investigate processes using this pipe. Kill the process and scan for malware. "
                                f"Use: Get-Process | Where-Object {{ $_.Handles }} to find the owner.",
                )
                findings.append(finding)
                print_finding(finding)
                break

    print(f"  [i] Analyzed {len(pipes)} pipes, {suspicious_count} suspicious")
    print(f"  [i] Named pipe scan complete. {len(findings)} findings.")
    return findings
