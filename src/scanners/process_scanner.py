"""
process_scanner.py - Running process analysis module.
Context-aware detection that respects digital signatures, trusted vendors,
and known developer tools. Only flags genuinely suspicious processes.

Includes LOLBin command-line abuse detection and general suspicious
command-line pattern analysis for non-trusted processes.
"""

import os
import re
from typing import List, Set, Dict, Optional, Tuple

import psutil

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle, SYSTEM_PROCESSES,
    check_file_signature, is_trusted_signer,
    is_known_dev_tool, is_suspicious_userland_path, is_os_native_path,
    print_section, print_finding,
)

# ---- Typosquatting map: wrong_name → correct_system_name ----
TYPOSQUAT_MAP = {
    "svch0st.exe": "svchost.exe",
    "scvhost.exe": "svchost.exe",
    "svchosts.exe": "svchost.exe",
    "svchost32.exe": "svchost.exe",
    "svchost64.exe": "svchost.exe",
    "lsas.exe": "lsass.exe",
    "1sass.exe": "lsass.exe",
    "lsasss.exe": "lsass.exe",
    "csrs.exe": "csrss.exe",
    "cssrs.exe": "csrss.exe",
    "csrse.exe": "csrss.exe",
    "expIorer.exe": "explorer.exe",  # uppercase I vs lowercase l
    "exp1orer.exe": "explorer.exe",
    "explor3r.exe": "explorer.exe",
    "iexplorer.exe": "explorer.exe",
    "taskh0st.exe": "taskhostw.exe",
    "dllh0st.exe": "dllhost.exe",
    "spoo1sv.exe": "spoolsv.exe",
    "win1ogon.exe": "winlogon.exe",
    "winl0gon.exe": "winlogon.exe",
}

# ---- Suspicious parent → child relationships ----
SUSPICIOUS_PARENT_CHILD = {
    "winword.exe": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe"},
    "excel.exe": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "powerpnt.exe": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"},
    "outlook.exe": {"powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe"},
    "msaccess.exe": {"powershell.exe", "cmd.exe", "wscript.exe"},
    "mspub.exe": {"powershell.exe", "cmd.exe", "wscript.exe"},
    "onenote.exe": {"powershell.exe", "cmd.exe"},
    "mshta.exe": {"powershell.exe", "cmd.exe"},
    "wscript.exe": {"powershell.exe", "cmd.exe"},
    "cscript.exe": {"powershell.exe", "cmd.exe"},
}

# ---------------------------------------------------------------------------
# LOLBin Command-Line Abuse Patterns (CHECK 4)
# ---------------------------------------------------------------------------
# Maps binary name (without .exe, lowercase) to a list of
# (compiled_regex, description, RiskLevel, mitre_id) tuples.
# Regex compiled at import time for performance.
# LOLBins are Microsoft-signed by nature — always check regardless of trust.
# ---------------------------------------------------------------------------

LOLBIN_PATTERNS: Dict[str, List[Tuple[re.Pattern, str, RiskLevel, str]]] = {
    "certutil": [
        (re.compile(r"-urlcache", re.IGNORECASE),
         "Certutil URL cache download", RiskLevel.HIGH, "T1105"),
        (re.compile(r"-encode\b", re.IGNORECASE),
         "Certutil encode (data obfuscation)", RiskLevel.MEDIUM, "T1140"),
        (re.compile(r"-decode\b", re.IGNORECASE),
         "Certutil decode (payload staging)", RiskLevel.HIGH, "T1140"),
    ],
    "mshta": [
        (re.compile(r"javascript:", re.IGNORECASE),
         "MSHTA javascript execution", RiskLevel.HIGH, "T1218.005"),
        (re.compile(r"vbscript:", re.IGNORECASE),
         "MSHTA vbscript execution", RiskLevel.HIGH, "T1218.005"),
        (re.compile(r"https?://", re.IGNORECASE),
         "MSHTA remote HTA fetch", RiskLevel.HIGH, "T1218.005"),
    ],
    "rundll32": [
        (re.compile(r"javascript:", re.IGNORECASE),
         "Rundll32 javascript execution", RiskLevel.HIGH, "T1218.011"),
        (re.compile(r"\\temp\\|\\tmp\\|\\appdata\\", re.IGNORECASE),
         "Rundll32 loading DLL from suspicious path", RiskLevel.HIGH, "T1218.011"),
        (re.compile(r"shell32\.dll.*#\d+", re.IGNORECASE),
         "Rundll32 shell32 ordinal call", RiskLevel.MEDIUM, "T1218.011"),
    ],
    "regsvr32": [
        (re.compile(r"/s\s+/n\s+/u\s+/i:", re.IGNORECASE),
         "Regsvr32 squiblydoo (scriptlet execution)", RiskLevel.HIGH, "T1218.010"),
        (re.compile(r"scrobj\.dll", re.IGNORECASE),
         "Regsvr32 COM scriptlet loading", RiskLevel.HIGH, "T1218.010"),
        (re.compile(r"https?://", re.IGNORECASE),
         "Regsvr32 remote scriptlet fetch", RiskLevel.HIGH, "T1218.010"),
    ],
    "bitsadmin": [
        (re.compile(r"/transfer\b", re.IGNORECASE),
         "BitsAdmin file transfer", RiskLevel.HIGH, "T1197"),
        (re.compile(r"/create\b.*(?:/addfile|/setnotifycmdline)", re.IGNORECASE),
         "BitsAdmin job with execution", RiskLevel.HIGH, "T1197"),
    ],
    "wmic": [
        (re.compile(r"process\s+call\s+create", re.IGNORECASE),
         "WMIC remote process creation", RiskLevel.HIGH, "T1047"),
        (re.compile(r"format\s*:\s*\"?https?://", re.IGNORECASE),
         "WMIC XSL script execution", RiskLevel.HIGH, "T1220"),
    ],
    "powershell": [
        (re.compile(r"-enc\b|-encodedcommand\b", re.IGNORECASE),
         "Encoded PowerShell command", RiskLevel.HIGH, "T1059.001"),
        (re.compile(r"\bIEX\b|invoke-expression", re.IGNORECASE),
         "Invoke-Expression (IEX)", RiskLevel.HIGH, "T1059.001"),
        (re.compile(r"downloadstring|downloadfile|invoke-webrequest", re.IGNORECASE),
         "PowerShell network download", RiskLevel.HIGH, "T1105"),
        (re.compile(r"-w\s+hidden|-windowstyle\s+hidden", re.IGNORECASE),
         "Hidden PowerShell window", RiskLevel.MEDIUM, "T1564.003"),
        (re.compile(r"-nop\b|-noprofile\b", re.IGNORECASE),
         "PowerShell no-profile flag", RiskLevel.MEDIUM, "T1059.001"),
        (re.compile(r"-e\s+[A-Za-z0-9+/=]{40,}", re.IGNORECASE),
         "Large encoded PowerShell payload", RiskLevel.HIGH, "T1059.001"),
        (re.compile(r"frombase64string", re.IGNORECASE),
         "Base64 string decoding", RiskLevel.HIGH, "T1059.001"),
    ],
    "cmd": [
        (re.compile(r"/c\s+.*(?:powershell|wscript|cscript|mshta|certutil|bitsadmin)", re.IGNORECASE),
         "CMD spawning interpreter/LOLBin", RiskLevel.HIGH, "T1059.003"),
        (re.compile(r"/c\s+.*(?:echo\s.*\|)", re.IGNORECASE),
         "CMD pipe chain (potential obfuscation)", RiskLevel.MEDIUM, "T1059.003"),
    ],
}

# Pre-built set for O(1) LOLBin name lookup
LOLBIN_NAMES: Set[str] = set(LOLBIN_PATTERNS.keys())

# ---------------------------------------------------------------------------
# General Suspicious Command-Line Patterns (CHECK 5)
# ---------------------------------------------------------------------------
# Applied to non-LOLBin, non-trusted-signed processes only.
# ---------------------------------------------------------------------------

GENERAL_SUSPICIOUS_CMDLINE: List[Tuple[re.Pattern, str, RiskLevel, str]] = [
    (re.compile(r"[A-Za-z0-9+/=]{100,}"),
     "Long Base64-like argument (possible encoded payload)", RiskLevel.MEDIUM, "T1027"),
    (re.compile(r"https?://", re.IGNORECASE),
     "URL in process command line", RiskLevel.MEDIUM, "T1105"),
    (re.compile(r"-hidden|-windowstyle\s+hidden", re.IGNORECASE),
     "Hidden window execution", RiskLevel.MEDIUM, "T1564.003"),
    (re.compile(r"\\temp\\.*\.(exe|dll|bat|ps1|vbs|js)\b", re.IGNORECASE),
     "Execution target in Temp directory", RiskLevel.MEDIUM, "T1204.002"),
    (re.compile(r"\\appdata\\.*\.(exe|dll|bat|ps1|vbs|js)\b", re.IGNORECASE),
     "Execution target in AppData directory", RiskLevel.MEDIUM, "T1204.002"),
]


# ---------------------------------------------------------------------------
# Helper Functions
# ---------------------------------------------------------------------------

def _get_process_info() -> List[Dict]:
    """Collect process information efficiently."""
    procs = []
    for proc in psutil.process_iter(["pid", "name", "exe", "ppid"]):
        try:
            info = proc.info
            procs.append({
                "pid": info["pid"],
                "name": info.get("name", ""),
                "exe": info.get("exe") or "",
                "ppid": info.get("ppid", 0),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
    return procs


def _has_network_connections(pid: int) -> bool:
    """Check if a process has active network connections."""
    try:
        conns = psutil.Process(pid).net_connections(kind="inet")
        return any(c.status == "ESTABLISHED" and c.raddr for c in conns)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False


def _get_cmdline(pid: int) -> Optional[str]:
    """Get process command line as a single string.

    Fetches cmdline lazily per-PID to avoid AccessDenied overhead
    for system processes that are skipped anyway.

    Args:
        pid: Process ID to query.

    Returns:
        Space-joined command line string, or None if inaccessible.
    """
    try:
        proc = psutil.Process(pid)
        parts = proc.cmdline()
        if parts:
            return " ".join(parts)
    except (psutil.NoSuchProcess, psutil.AccessDenied,
            psutil.ZombieProcess, OSError):
        pass
    return None


def _check_lolbin_cmdline(name_lower: str, cmdline: str,
                          proc: Dict) -> List[Finding]:
    """Check a LOLBin process command line against known abuse patterns.

    Args:
        name_lower: Process name in lowercase (e.g. "certutil.exe").
        cmdline: Full command line string.
        proc: Process info dict with pid, name, exe, ppid.

    Returns:
        List of Finding objects for matched patterns.
    """
    findings: List[Finding] = []
    bin_key = name_lower.removesuffix(".exe")
    patterns = LOLBIN_PATTERNS.get(bin_key)
    if not patterns:
        return findings

    matched_descriptions: Set[str] = set()
    for regex, description, risk, mitre_id in patterns:
        if description in matched_descriptions:
            continue
        if regex.search(cmdline):
            matched_descriptions.add(description)
            findings.append(Finding(
                module="Process Scanner",
                risk=risk,
                title=f"LOLBin abuse: {proc['name']} \u2014 {description}",
                description=(
                    f"Living-off-the-Land binary '{proc['name']}' executed "
                    f"with suspicious arguments."
                ),
                details={
                    "process": proc["name"],
                    "path": proc["exe"],
                    "pid": proc["pid"],
                    "cmdline": cmdline[:2000],
                    "pattern_matched": description,
                },
                mitre_id=mitre_id,
                remediation=(
                    f"Investigate why {proc['name']} (PID {proc['pid']}) "
                    f"was invoked with these arguments. Kill if unauthorized."
                ),
            ))
    return findings


def _check_general_cmdline(cmdline: str, proc: Dict) -> List[Finding]:
    """Check a non-trusted process command line for suspicious patterns.

    Applied only to processes that are NOT LOLBins and NOT trusted-signed.

    Args:
        cmdline: Full command line string.
        proc: Process info dict with pid, name, exe, ppid.

    Returns:
        List of Finding objects for matched patterns.
    """
    findings: List[Finding] = []

    # Electron child processes pass their own AppData path and long encoded
    # config in cmdline.  These are benign worker processes, not malware.
    _ELECTRON_CHILD_ARGS = (
        "--type=renderer", "--type=gpu-process", "--type=utility",
        "--type=broker", "--type=crashpad-handler",
    )
    if any(marker in cmdline for marker in _ELECTRON_CHILD_ARGS):
        return findings

    matched_descriptions: Set[str] = set()
    for regex, description, risk, mitre_id in GENERAL_SUSPICIOUS_CMDLINE:
        if description in matched_descriptions:
            continue
        if regex.search(cmdline):
            matched_descriptions.add(description)
            findings.append(Finding(
                module="Process Scanner",
                risk=risk,
                title=f"Suspicious cmdline: {proc['name']} \u2014 {description}",
                description=(
                    f"Process '{proc['name']}' has suspicious "
                    f"command-line arguments."
                ),
                details={
                    "process": proc["name"],
                    "path": proc["exe"],
                    "pid": proc["pid"],
                    "cmdline": cmdline[:2000],
                    "pattern_matched": description,
                },
                mitre_id=mitre_id,
                remediation=(
                    f"Investigate process {proc['name']} (PID {proc['pid']}). "
                    f"Verify its legitimacy."
                ),
            ))
    return findings


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------

def scan() -> List[Finding]:
    """Run the process scanner and return findings.

    Two-phase analysis:
      Phase A — Name-deduplicated checks (typosquatting, parent-child, unsigned).
      Phase B — Per-instance command-line analysis (LOLBin abuse, general suspicion).
    """
    print_section("PROCESS SCANNER - Context-Aware Process Analysis")
    findings = []
    throttle = IOThrottle(ops_per_batch=20, sleep_seconds=0.03)

    print("  [i] Enumerating running processes...")
    processes = _get_process_info()
    pid_map = {p["pid"]: p for p in processes}
    print(f"  [i] Found {len(processes)} running processes")

    # =================================================================
    # PHASE A: Name-deduplicated checks (existing logic)
    # Checks 1-3: typosquatting, parent-child, unsigned + network
    # =================================================================
    checked: Set[str] = set()
    own_pid = os.getpid()

    for proc in processes:
        name = proc["name"]
        exe_path = proc["exe"]
        pid = proc["pid"]
        name_lower = name.lower()

        if not name or name_lower in checked:
            continue
        if name_lower in SYSTEM_PROCESSES:
            continue
        # Skip our own process (the scanner itself)
        if pid == own_pid:
            continue

        checked.add(name_lower)

        # ---- CHECK 1: Typosquatting ----
        if name_lower in TYPOSQUAT_MAP:
            real_name = TYPOSQUAT_MAP[name_lower]
            finding = Finding(
                module="Process Scanner",
                risk=RiskLevel.HIGH,
                title=f"Typosquatted process: {name} (mimics {real_name})",
                description=f"Process name '{name}' closely resembles '{real_name}', a known system process.",
                details={
                    "process": name,
                    "mimics": real_name,
                    "path": exe_path,
                    "pid": pid,
                },
                mitre_id="T1036.005",
                remediation=f"Kill the process (PID {pid}) and delete the binary. Investigate its origin.",
            )
            findings.append(finding)
            print_finding(finding)
            continue

        # ---- CHECK 2: Suspicious parent→child relationship ----
        ppid = proc.get("ppid", 0)
        parent = pid_map.get(ppid, {})
        parent_name = parent.get("name", "").lower()

        if parent_name in SUSPICIOUS_PARENT_CHILD:
            bad_children = SUSPICIOUS_PARENT_CHILD[parent_name]
            if name_lower in bad_children:
                finding = Finding(
                    module="Process Scanner",
                    risk=RiskLevel.HIGH,
                    title=f"Suspicious parent\u2192child: {parent.get('name', '')} \u2192 {name}",
                    description="Office/scripting application spawning a command interpreter is a strong malware indicator.",
                    details={
                        "parent_process": parent.get("name", ""),
                        "parent_path": parent.get("exe", ""),
                        "child_process": name,
                        "child_path": exe_path,
                        "parent_pid": ppid,
                        "child_pid": pid,
                    },
                    mitre_id="T1059",
                    remediation=f"Kill the child process '{name}' (PID {pid}). Investigate the parent for macro/exploit execution.",
                )
                findings.append(finding)
                print_finding(finding)
                continue

        # ---- CHECK 3: Unsigned binary from suspicious path + network ----
        # Skip known dev tools and OS-native paths entirely
        if not exe_path:
            continue

        if is_known_dev_tool(name, exe_path):
            continue

        if is_os_native_path(exe_path):
            continue

        if not is_suspicious_userland_path(exe_path):
            continue

        # At this point: process is from a suspicious path AND is NOT a known dev tool
        sig = check_file_signature(exe_path)
        throttle.tick()

        # If signed by a trusted vendor → skip entirely
        if sig.get("trusted"):
            continue

        # If signed at all (but not by a top-tier vendor) → lower risk
        if sig.get("signed"):
            continue

        # Unsigned binary from suspicious path
        has_net = _has_network_connections(pid)

        if has_net:
            finding = Finding(
                module="Process Scanner",
                risk=RiskLevel.HIGH,
                title=f"Unsigned process with network: {name}",
                description="Unsigned binary from user-writable directory with active network connections.",
                details={
                    "process": name,
                    "path": exe_path,
                    "pid": pid,
                    "signed": False,
                    "network_active": True,
                },
                mitre_id="T1036",
                remediation=f"Kill the process (PID {pid}). Block its outbound connections. Investigate the binary.",
            )
            findings.append(finding)
            print_finding(finding)
        else:
            finding = Finding(
                module="Process Scanner",
                risk=RiskLevel.MEDIUM,
                title=f"Unsigned process from suspicious path: {name}",
                description="Unsigned binary from user-writable directory.",
                details={
                    "process": name,
                    "path": exe_path,
                    "pid": pid,
                    "signed": False,
                    "network_active": False,
                },
                mitre_id="T1036",
                remediation="Investigate the process and its source. Delete if unauthorized.",
            )
            findings.append(finding)
            print_finding(finding)

    # =================================================================
    # PHASE B: Per-instance command-line analysis
    # Check 4: LOLBin cmdline abuse (always, per PID)
    # Check 5: General suspicious cmdline (non-trusted only)
    # =================================================================
    print("  [i] Analyzing process command lines...")
    cmdline_checked_pids: Set[int] = set()

    for proc in processes:
        name = proc["name"]
        exe_path = proc["exe"]
        pid = proc["pid"]
        name_lower = name.lower()

        if not name or name_lower in SYSTEM_PROCESSES:
            continue
        if pid == own_pid:
            continue
        if pid in cmdline_checked_pids:
            continue
        cmdline_checked_pids.add(pid)

        # ---- CHECK 4: LOLBin command-line abuse ----
        bin_key = name_lower.removesuffix(".exe")
        if bin_key in LOLBIN_NAMES:
            cmdline = _get_cmdline(pid)
            if cmdline:
                lolbin_findings = _check_lolbin_cmdline(name_lower, cmdline, proc)
                for f in lolbin_findings:
                    findings.append(f)
                    print_finding(f)
            continue  # LOLBin handled — skip general check for same process

        # ---- CHECK 5: General suspicious cmdline (non-trusted only) ----
        if not exe_path:
            continue

        # Same filters as Check 3: skip dev tools and OS-native paths
        if is_known_dev_tool(name, exe_path):
            continue
        if is_os_native_path(exe_path):
            continue

        # Check signature — only proceed for non-trusted
        sig = check_file_signature(exe_path)
        throttle.tick()

        if sig.get("trusted"):
            continue

        # Fetch cmdline for non-trusted process
        cmdline = _get_cmdline(pid)
        if cmdline:
            general_findings = _check_general_cmdline(cmdline, proc)
            for f in general_findings:
                findings.append(f)
                print_finding(f)

    print(f"  [i] Process scan complete. {len(findings)} findings.")
    return findings
