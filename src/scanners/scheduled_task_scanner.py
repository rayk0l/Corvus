"""
scheduled_task_scanner.py - Deep Scheduled Task XML analysis module.

Parses Windows Scheduled Task XML files from C:\\Windows\\System32\\Tasks\\
for suspicious configurations that may indicate persistence or backdoors.

Complements persistence_scanner.py (which uses schtasks CSV output) by
providing deep XML-level inspection: hidden flags, encoded payloads,
privilege levels, disabled-but-suspicious dormant tasks.

Requires Administrator privileges for full access to the Tasks directory.
"""

import os
import re
from typing import List, Dict, Optional
from xml.etree import ElementTree as ET

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    is_os_native_path, is_known_dev_tool,
    check_file_signature,
    print_section, print_finding,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

TASKS_DIR = r"C:\Windows\System32\Tasks"

# XML namespace used by Windows Task Scheduler
_NS = {"ts": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

# LOLBin targets — executables commonly abused in scheduled tasks
_LOLBIN_TARGETS = {
    "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "cmd.exe", "cmd",
    "mshta.exe", "mshta",
    "certutil.exe", "certutil",
    "wscript.exe", "wscript",
    "cscript.exe", "cscript",
    "rundll32.exe", "rundll32",
    "regsvr32.exe", "regsvr32",
    "bitsadmin.exe", "bitsadmin",
    "msiexec.exe", "msiexec",
}

# Suspicious argument patterns (compiled regex)
_SUSPICIOUS_ARG_PATTERNS: List[tuple] = [
    (re.compile(r"-e(nc|ncodedcommand)\b", re.IGNORECASE),
     "Encoded PowerShell command", "T1059.001"),
    (re.compile(r"[A-Za-z0-9+/=]{80,}"),
     "Long Base64-like payload", "T1027"),
    (re.compile(r"(iex|invoke-expression|downloadstring|downloadfile|"
                r"invoke-webrequest|start-bitstransfer)", re.IGNORECASE),
     "PowerShell download/execute pattern", "T1059.001"),
    (re.compile(r"-w(indowstyle)?\s+hidden", re.IGNORECASE),
     "Hidden window execution", "T1564.003"),
    (re.compile(r"\\appdata\\", re.IGNORECASE),
     "AppData path target", "T1204.002"),
    (re.compile(r"\\temp\\", re.IGNORECASE),
     "Temp directory target", "T1204.002"),
    (re.compile(r"-urlcache|-decode|-encode", re.IGNORECASE),
     "Certutil abuse pattern", "T1140"),
    (re.compile(r"/s\s+/n\s+.*scrobj", re.IGNORECASE),
     "Regsvr32 scriptlet loading", "T1218.010"),
    (re.compile(r"/transfer\b", re.IGNORECASE),
     "BitsAdmin transfer", "T1197"),
    (re.compile(r"javascript:|vbscript:|http://|https://", re.IGNORECASE),
     "Script/URL in arguments", "T1218.005"),
]

# Script file extensions in task commands
_SCRIPT_EXTENSIONS = {".ps1", ".vbs", ".js", ".bat", ".cmd", ".hta", ".wsf"}

# Known safe task authors (lowercase)
_SAFE_AUTHORS = {
    "microsoft", "microsoft corporation",
    "microsoft windows", "system",
    "\\system", "local service", "network service",
    "adobe", "adobe systems", "google", "apple",
}

# Windows system task path namespace — tasks under this path are OS-native
_WINDOWS_TASK_NAMESPACE = "\\microsoft\\windows\\"

# Maximum tasks to scan (safety limit)
_MAX_TASKS = 2000


# ---------------------------------------------------------------------------
# XML Parsing
# ---------------------------------------------------------------------------

def _parse_task_xml(filepath: str) -> Optional[Dict]:
    """Parse a Scheduled Task XML file and extract relevant fields.

    Returns a dict with task configuration, or None if unparseable.
    """
    try:
        tree = ET.parse(filepath)
        root = tree.getroot()
    except (ET.ParseError, OSError, PermissionError):
        return None

    # Handle both namespaced and non-namespaced XML
    ns = ""
    if root.tag.startswith("{"):
        ns = root.tag.split("}")[0] + "}"

    def find(parent, tag):
        """Find element with or without namespace."""
        el = parent.find(f"{ns}{tag}")
        if el is None:
            el = parent.find(tag)
        return el

    def find_text(parent, tag, default=""):
        """Find element text with fallback."""
        el = find(parent, tag)
        return el.text.strip() if el is not None and el.text else default

    result = {
        "filepath": filepath,
        "task_name": os.path.basename(filepath),
        "author": "",
        "description": "",
        "hidden": False,
        "enabled": True,
        "run_level": "",
        "commands": [],   # List of {"command": ..., "arguments": ...}
    }

    # Registration Info
    reg_info = find(root, "RegistrationInfo")
    if reg_info is not None:
        result["author"] = find_text(reg_info, "Author")
        result["description"] = find_text(reg_info, "Description")

    # Settings
    settings = find(root, "Settings")
    if settings is not None:
        hidden_el = find(settings, "Hidden")
        if hidden_el is not None and hidden_el.text:
            result["hidden"] = hidden_el.text.strip().lower() == "true"
        enabled_el = find(settings, "Enabled")
        if enabled_el is not None and enabled_el.text:
            result["enabled"] = enabled_el.text.strip().lower() != "false"

    # Principals (privilege level)
    principals = find(root, "Principals")
    if principals is not None:
        principal = find(principals, "Principal")
        if principal is not None:
            result["run_level"] = find_text(principal, "RunLevel")

    # Actions (commands to execute)
    actions = find(root, "Actions")
    if actions is not None:
        for exec_el in actions:
            tag = exec_el.tag.replace(ns, "")
            if tag == "Exec":
                cmd = find_text(exec_el, "Command")
                args = find_text(exec_el, "Arguments")
                if cmd:
                    result["commands"].append({
                        "command": cmd,
                        "arguments": args,
                    })

    return result


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------

def _is_safe_author(author: str) -> bool:
    """Check if the task author is a known safe vendor."""
    if not author:
        return False
    author_lower = author.lower().strip()
    # Windows resource string references like "$(@%SystemRoot%\system32\ClipUp.exe,-100)"
    # are used by built-in Windows tasks.
    if author_lower.startswith("$(@%systemroot%"):
        return True
    for safe in _SAFE_AUTHORS:
        if author_lower == safe or author_lower.startswith(safe + " "):
            return True
    return False


# Known safe task name patterns → expected binary names.
# Multi-condition: name matches AND binary matches AND binary is signed.
_KNOWN_SAFE_TASKS: Dict[str, List[str]] = {
    "zoomupdatetask": ["zoom.exe", "zoominstaller.exe"],
    "googleupdate": ["googleupdate.exe"],
    "microsoftedgeupdate": ["msedgeupdate.exe", "microsoftedgeupdate.exe"],
    "onedrive": ["onedrive.exe", "onedrivestanaloneupdater.exe"],
    "adobeacrobatupdate": ["adobearm.exe", "armsvc.exe"],
    "mozillamaintenance": ["maintenanceservice.exe"],
    "ccleaner": ["ccleaner.exe", "ccleaner64.exe"],
    "npcapwatchdog": ["checkstatus.bat"],
}


def _is_known_safe_task(task_name: str, task_binary_path: str) -> bool:
    """Check if scheduled task is a known legitimate application task.

    Requires ALL of:
      1. Task name matches a known pattern
      2. Binary name matches expected binary for that pattern
      3. Binary is signed (or for .bat: parent dir is in Program Files)

    Attacker can rename task to "ZoomUpdateTask" but can't easily
    fake binary name + valid signature together.
    """
    name_lower = task_name.lower()
    matched_binaries = None
    for pattern, expected in _KNOWN_SAFE_TASKS.items():
        if pattern in name_lower:
            matched_binaries = expected
            break

    if not matched_binaries:
        return False

    # Condition 2: binary name matches
    # Strip surrounding quotes — task XML often wraps paths in quotes
    clean_path = task_binary_path.strip('"').strip("'")
    binary_name = os.path.basename(clean_path).lower()
    if binary_name not in [b.lower() for b in matched_binaries]:
        return False  # Name matches but binary doesn't — SUSPICIOUS

    # Condition 3: binary is signed or in safe path (.bat exception)
    if clean_path and os.path.isfile(clean_path):
        if binary_name.endswith((".bat", ".cmd")):
            # Scripts can't be signed — check they're in Program Files
            path_lower = clean_path.lower()
            return "\\program files\\" in path_lower or "\\program files (x86)\\" in path_lower
        sig = check_file_signature(clean_path)
        if sig.get("signed"):
            return True

    return False


def _analyze_task(task: Dict) -> List[Finding]:
    """Analyze a parsed task for suspicious indicators.

    Returns a list of findings (may be empty for benign tasks).
    """
    findings = []
    task_name = task["task_name"]
    filepath = task["filepath"]
    author = task["author"]
    is_hidden = task["hidden"]
    is_enabled = task["enabled"]
    run_level = task["run_level"]
    commands = task["commands"]

    if not commands:
        return findings

    # Tasks under \Microsoft\Windows\ namespace are OS-native system tasks.
    # They commonly use hidden flags, LOLBins with elevated privileges, and
    # resource string authors — all legitimate for Windows maintenance.
    is_windows_task = _WINDOWS_TASK_NAMESPACE in filepath.lower()
    if is_windows_task:
        # Still check for LOLBin + suspicious args (rare but possible hijack)
        # but skip hidden-only, elevated-LOLBin-only, and author-based flags.
        _has_suspicious_args = False
        for cmd_info in commands:
            full_cmd = f"{cmd_info['command']} {cmd_info['arguments']}".strip()
            for regex, _, _ in _SUSPICIOUS_ARG_PATTERNS:
                if regex.search(full_cmd):
                    _has_suspicious_args = True
                    break
            if _has_suspicious_args:
                break
        if not _has_suspicious_args:
            return findings

    # Multi-condition safe check for known third-party tasks.
    # Requires: name match + binary match + signed.
    for cmd_info in commands:
        if _is_known_safe_task(task_name, cmd_info["command"]):
            return findings

    for cmd_info in commands:
        command = cmd_info["command"]
        arguments = cmd_info["arguments"]
        full_command = f"{command} {arguments}".strip()
        command_basename = os.path.basename(command).lower()

        is_lolbin = command_basename in _LOLBIN_TARGETS

        # Check argument patterns
        matched_patterns = []
        primary_mitre = "T1053.005"

        for regex, desc, mitre_id in _SUSPICIOUS_ARG_PATTERNS:
            if regex.search(full_command):
                matched_patterns.append(desc)
                primary_mitre = mitre_id  # Use most specific MITRE

        # Check for script file targets
        is_script_target = False
        cmd_lower = command.lower()
        args_lower = arguments.lower()
        for ext in _SCRIPT_EXTENSIONS:
            if ext in cmd_lower or ext in args_lower:
                is_script_target = True
                break

        # ---- Risk determination ----
        risk = None
        title = None
        desc = None

        if is_lolbin and matched_patterns:
            # LOLBin with suspicious args = strong indicator
            risk = RiskLevel.HIGH
            title = f"Suspicious scheduled task: {task_name}"
            desc = (
                f"Task executes {command_basename} with suspicious arguments: "
                f"{', '.join(matched_patterns[:3])}"
            )
        elif is_hidden and not _is_safe_author(author):
            # Hidden task from non-Microsoft author
            risk = RiskLevel.HIGH
            title = f"Hidden scheduled task: {task_name}"
            desc = (
                f"Task is marked as hidden with non-standard author "
                f"'{author or 'Unknown'}'. Hidden tasks are commonly "
                "used by malware for persistence."
            )
        elif matched_patterns and not _is_safe_author(author):
            # Suspicious patterns without LOLBin
            risk = RiskLevel.HIGH if len(matched_patterns) >= 2 else RiskLevel.MEDIUM
            title = f"Suspicious scheduled task: {task_name}"
            desc = (
                f"Task contains suspicious patterns: "
                f"{', '.join(matched_patterns[:3])}"
            )
        elif is_lolbin and not _is_safe_author(author):
            # LOLBin target but no suspicious args — could be legit admin task
            # Only flag if also has elevated privileges
            if run_level.lower() == "highestavailable":
                risk = RiskLevel.MEDIUM
                title = f"Elevated LOLBin task: {task_name}"
                desc = (
                    f"Task runs {command_basename} with highest privileges. "
                    "Verify this is an authorized administrative task."
                )
        elif is_script_target and not _is_safe_author(author):
            # Script file target from non-standard author
            risk = RiskLevel.MEDIUM
            title = f"Script-based scheduled task: {task_name}"
            desc = (
                f"Task executes a script file: {command}. "
                "Script-based tasks from unknown authors require review."
            )

        # Dormant but suspicious: disabled task with suspicious config
        if risk and not is_enabled:
            # Downgrade but still report — dormant threats matter
            if risk == RiskLevel.HIGH:
                risk = RiskLevel.MEDIUM
            title = f"Disabled suspicious task: {task_name}"
            desc = f"(DISABLED) {desc}"

        if risk:
            findings.append(Finding(
                module="Scheduled Task Scanner",
                risk=risk,
                title=title,
                description=desc,
                details={
                    "task_name": task_name,
                    "task_path": filepath,
                    "author": author or "Unknown",
                    "command": command[:500],
                    "arguments": arguments[:1000],
                    "hidden": is_hidden,
                    "enabled": is_enabled,
                    "run_level": run_level,
                    "matched_patterns": matched_patterns[:5],
                },
                mitre_id=primary_mitre,
                remediation=(
                    f"Review scheduled task '{task_name}'. If unauthorized, "
                    "delete it: schtasks /delete /tn \"<name>\" /f"
                ),
            ))

    return findings


# ---------------------------------------------------------------------------
# Main Scanner
# ---------------------------------------------------------------------------

def scan() -> List[Finding]:
    """Scan Windows Scheduled Task XML files for suspicious configurations.

    Parses task XMLs from C:\\Windows\\System32\\Tasks\\ for:
      1. LOLBin command targets with suspicious arguments
      2. Hidden tasks from non-standard authors
      3. Encoded/obfuscated payloads
      4. Elevated privilege tasks with suspicious commands
      5. Disabled-but-suspicious dormant tasks
    """
    print_section("SCHEDULED TASK SCANNER - Deep Task XML Analysis")
    findings: List[Finding] = []
    throttle = IOThrottle(ops_per_batch=100, sleep_seconds=0.01)

    if not os.path.isdir(TASKS_DIR):
        print(f"  [!] Tasks directory not found: {TASKS_DIR}")
        print("  [i] Run as Administrator for scheduled task analysis.")
        return findings

    # Collect all task files (recursive)
    task_files = []
    try:
        for root_dir, dirs, files in os.walk(TASKS_DIR):
            for fname in files:
                fpath = os.path.join(root_dir, fname)
                task_files.append(fpath)
                if len(task_files) >= _MAX_TASKS:
                    break
            if len(task_files) >= _MAX_TASKS:
                break
    except PermissionError:
        print("  [!] Access denied to Tasks directory. Run as Administrator.")
        return findings

    print(f"  [i] Found {len(task_files)} scheduled task file(s)")

    parsed = 0
    errors = 0

    for fpath in task_files:
        throttle.tick()
        task = _parse_task_xml(fpath)
        if task is None:
            errors += 1
            continue

        parsed += 1
        task_findings = _analyze_task(task)
        for f in task_findings:
            findings.append(f)
            print_finding(f)

    print(f"  [i] Parsed {parsed} tasks ({errors} unreadable). "
          f"{len(findings)} finding(s).")
    return findings
