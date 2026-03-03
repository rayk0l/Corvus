"""
persistence_scanner.py - Persistence mechanism scanner module.
Checks registry Run keys, startup folder, scheduled tasks, and WMI
event subscriptions for suspicious persistence entries.
Context-aware: whitelists known legitimate applications that autostart
from AppData to avoid false positives.
"""

import os
import re
import subprocess
import csv
import io
from typing import List

from scanner_core.utils import Finding, RiskLevel, print_section, print_finding

# Suspicious patterns in persistence entries
SUSPICIOUS_PATTERNS = [
    (r"-enc\b", "Encoded command (-enc)", RiskLevel.HIGH, "T1059.001"),
    (r"frombase64string", "Base64 decoding (FromBase64String)", RiskLevel.HIGH, "T1059.001"),
    (r"\bIEX\b", "Invoke-Expression (IEX)", RiskLevel.HIGH, "T1059.001"),
    (r"invoke-expression", "Invoke-Expression", RiskLevel.HIGH, "T1059.001"),
    (r"downloadstring", "DownloadString", RiskLevel.HIGH, "T1105"),
    (r"downloadfile", "DownloadFile", RiskLevel.HIGH, "T1105"),
    (r"\bbitsadmin\b", "BitsAdmin transfer", RiskLevel.HIGH, "T1197"),
    (r"certutil\s.*-urlcache", "Certutil URL cache download", RiskLevel.HIGH, "T1105"),
    (r"-w\s+hidden", "Hidden window (-w hidden)", RiskLevel.MEDIUM, "T1564.003"),
    (r"-windowstyle\s+hidden", "Hidden window style", RiskLevel.MEDIUM, "T1564.003"),
    (r"\b-nop\b", "No profile (-nop)", RiskLevel.MEDIUM, "T1059.001"),
    (r"bypass", "Execution policy bypass", RiskLevel.MEDIUM, "T1059.001"),
    (r"\\appdata\\", "Runs from AppData", RiskLevel.MEDIUM, "T1547.001"),
    (r"\\temp\\", "Runs from Temp", RiskLevel.MEDIUM, "T1547.001"),
    (r"\\tmp\\", "Runs from Tmp", RiskLevel.MEDIUM, "T1547.001"),
    (r"powershell.*-e\s+[A-Za-z0-9+/=]{20,}", "Encoded PowerShell payload", RiskLevel.HIGH, "T1059.001"),
    (r"mshta\s+(https?://|javascript:)", "MSHTA with remote/script content", RiskLevel.HIGH, "T1218.005"),
    (r"regsvr32\s+/s\s+/n\s+/u\s+/i:", "Regsvr32 squiblydoo", RiskLevel.HIGH, "T1218.010"),
]


# ---------------------------------------------------------------------------
# Known-safe autostart applications (lowercase substrings)
# These are legitimate apps that commonly register autostart from AppData
# ---------------------------------------------------------------------------
KNOWN_SAFE_AUTOSTART_APPS = [
    # Communication & Collaboration
    "notion", "teams", "msteams", "ms-teams", "zoom", "slack",
    "discord", "whatsapp", "telegram", "signal", "skype",
    "webex", "microsoft teams",
    # Cloud Storage & Sync
    "onedrive", "dropbox", "googledrive", "googledrivesync",
    "icloud", "box sync", "megasync",
    # Browsers
    "chrome", "msedge", "firefox", "brave", "opera", "vivaldi",
    # Development Tools
    "code.exe", "cursor", "antigravity", "github desktop",
    "visual studio", "jetbrains", "sublime",
    # Media & Entertainment
    "spotify", "itunes", "vlc",
    # Productivity
    "grammarly", "1password", "bitwarden", "lastpass",
    "todoist", "evernote",
    # Gaming
    "steam", "epicgames", "battle.net", "gog galaxy",
    # Hardware / Peripherals
    "logitech", "lghub", "razer", "corsair", "steelseries",
    # Adobe
    "adobe", "creative cloud", "acrobat",
    # Utilities
    "winrar", "7-zip", "everything", "powertoys",
    "sharex", "lightshot", "greenshot",
    # Remote Access (legitimate)
    "anydesk", "teamviewer",
    # Microsoft Store / MSIX apps
    "windowsapps",
]

# Known-safe autostart path prefixes (lowercase)
KNOWN_SAFE_AUTOSTART_PATHS = [
    "\\appdata\\local\\programs\\",          # Standard user install location
    "\\appdata\\local\\microsoft\\windowsapps\\",  # MSIX / Store apps
    "\\appdata\\local\\microsoft\\teams\\",
    "\\appdata\\local\\microsoft\\onedrive\\",
    "\\appdata\\local\\google\\",
    "\\appdata\\local\\brave",
    "\\appdata\\roaming\\zoom\\",
    "\\appdata\\roaming\\spotify\\",
    "\\appdata\\roaming\\discord\\",
    "\\appdata\\roaming\\slack\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\",
]


def _is_safe_autostart(value: str) -> bool:
    """Check if a persistence entry value is from a known safe application."""
    value_lower = value.lower()

    # Check known safe app names
    for safe_app in KNOWN_SAFE_AUTOSTART_APPS:
        if safe_app in value_lower:
            return True

    # Check known safe install paths
    for safe_path in KNOWN_SAFE_AUTOSTART_PATHS:
        if safe_path in value_lower:
            return True

    return False


def _check_patterns(value: str, source: str) -> List[Finding]:
    """Check a string against suspicious patterns and return findings.
    Context-aware: skips 'Runs from AppData/Temp' for known safe apps."""
    findings = []
    value_lower = value.lower()
    matched_titles = set()

    for pattern, title, risk, mitre in SUSPICIOUS_PATTERNS:
        if title in matched_titles:
            continue
        if re.search(pattern, value_lower, re.IGNORECASE):
            # For AppData/Temp location patterns, skip known safe autostart apps
            if title in ("Runs from AppData", "Runs from Temp", "Runs from Tmp"):
                if _is_safe_autostart(value):
                    continue

            matched_titles.add(title)
            findings.append(Finding(
                module="Persistence Scanner",
                risk=risk,
                title=f"Suspicious persistence: {title}",
                description=f"Suspicious pattern found in {source}.",
                details={
                    "source": source,
                    "pattern": title,
                    "value": value[:1000],
                },
                mitre_id=mitre,
                remediation=f"Remove or disable the suspicious persistence entry in {source}.",
            ))
    return findings


def _scan_registry() -> List[Finding]:
    """Scan registry Run keys for suspicious entries."""
    findings = []
    import winreg

    run_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\...\\RunOnce"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run"),
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\...\\RunOnce"),
    ]

    for hive, subkey, label in run_keys:
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    name, value, _ = winreg.EnumValue(key, i)
                    value_str = str(value)
                    source = f"Registry: {label}\\{name}"

                    # Check for suspicious patterns
                    pattern_findings = _check_patterns(value_str, source)
                    for f in pattern_findings:
                        f.details["registry_key"] = f"{label}\\{name}"
                        f.details["registry_value"] = value_str[:500]
                        findings.append(f)
                        print_finding(f)

                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except (OSError, PermissionError):
            continue

    return findings


def _scan_startup_folder() -> List[Finding]:
    """Scan the user's startup folder for suspicious items."""
    findings = []

    startup_paths = [
        os.path.expandvars(r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.expandvars(r"%ProgramData%\Microsoft\Windows\Start Menu\Programs\Startup"),
    ]

    suspicious_extensions = {".vbs", ".js", ".bat", ".cmd", ".ps1", ".wsf", ".hta"}

    for startup_dir in startup_paths:
        if not os.path.isdir(startup_dir):
            continue

        try:
            for item in os.listdir(startup_dir):
                full_path = os.path.join(startup_dir, item)
                ext = os.path.splitext(item)[1].lower()

                # Scripts in startup folder are suspicious
                if ext in suspicious_extensions:
                    finding = Finding(
                        module="Persistence Scanner",
                        risk=RiskLevel.HIGH,
                        title=f"Suspicious script in Startup: {item}",
                        description="A script file was found in the startup folder.",
                        details={
                            "source": "Startup Folder",
                            "path": full_path,
                            "extension": ext,
                        },
                        mitre_id="T1547.001",
                        remediation=f"Delete the suspicious script '{item}' from the Startup folder.",
                    )
                    findings.append(finding)
                    print_finding(finding)

                    # Check file content for patterns
                    if ext in {".bat", ".cmd", ".ps1", ".vbs", ".js"}:
                        try:
                            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read(4096)
                            pattern_findings = _check_patterns(content, f"Startup File: {item}")
                            findings.extend(pattern_findings)
                        except (PermissionError, OSError):
                            pass

                # .lnk files — check if they point to suspicious targets
                elif ext == ".lnk":
                    # We check the name for now; resolving .lnk requires COM
                    pass

        except (PermissionError, OSError):
            continue

    return findings


def _scan_scheduled_tasks() -> List[Finding]:
    """Scan scheduled tasks for suspicious entries."""
    findings = []

    try:
        result = subprocess.run(
            ["schtasks", "/query", "/fo", "CSV", "/v"],
            capture_output=True, text=True, timeout=30,
            encoding="utf-8", errors="replace"
        )
        output = result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        print("  [!] Could not query scheduled tasks.")
        return findings

    if not output:
        return findings

    try:
        reader = csv.DictReader(io.StringIO(output))
        for row in reader:
            task_name = row.get("TaskName", row.get('"TaskName"', ""))
            task_to_run = row.get("Task To Run", row.get('"Task To Run"', ""))
            author = row.get("Author", row.get('"Author"', ""))

            # Skip empty or system tasks
            if not task_to_run or task_to_run.strip() in ("N/A", ""):
                continue

            # Skip well-known Microsoft tasks
            if task_name and (
                task_name.startswith("\\Microsoft\\") or
                task_name.startswith("\\Apple\\") or
                "Google" in task_name
            ):
                continue

            # Check task action for suspicious patterns
            combined = f"{task_to_run} {task_name}"
            pattern_findings = _check_patterns(combined, f"Scheduled Task: {task_name}")

            for f in pattern_findings:
                f.details["task_name"] = task_name
                f.details["task_to_run"] = task_to_run[:500]
                f.details["author"] = author
                findings.append(f)
                print_finding(f)

    except (csv.Error, KeyError):
        # Fallback: try line-by-line parsing
        for line in output.split("\n"):
            if any(p[0] in line.lower() for p in SUSPICIOUS_PATTERNS[:8]):
                pattern_findings = _check_patterns(line, "Scheduled Task (raw)")
                findings.extend(pattern_findings)

    return findings


def _scan_wmi_persistence() -> List[Finding]:
    """Check for WMI event subscription persistence."""
    findings = []

    wmi_queries = [
        ("Event Consumers", ["wmic", "/namespace:\\\\root\\subscription", "path", "__EventConsumer", "get", "/format:list"]),
        ("Event Filters", ["wmic", "/namespace:\\\\root\\subscription", "path", "__EventFilter", "get", "/format:list"]),
        ("Filter-Consumer Bindings", ["wmic", "/namespace:\\\\root\\subscription", "path", "__FilterToConsumerBinding", "get", "/format:list"]),
    ]

    for label, cmd in wmi_queries:
        try:
            result = subprocess.run(
                cmd, shell=False, capture_output=True, text=True,
                timeout=15, encoding="utf-8", errors="replace"
            )
            output = result.stdout.strip()

            if not output or "No Instance(s)" in output or len(output) < 10:
                continue

            # If there are any WMI subscriptions, check for suspicious patterns
            if "CommandLineTemplate" in output or "ScriptText" in output:
                pattern_findings = _check_patterns(output, f"WMI {label}")
                if pattern_findings:
                    findings.extend(pattern_findings)
                    for f in pattern_findings:
                        print_finding(f)
                else:
                    # WMI subscriptions exist but no known patterns — still notable
                    finding = Finding(
                        module="Persistence Scanner",
                        risk=RiskLevel.MEDIUM,
                        title=f"WMI Event Subscription detected ({label})",
                        description="WMI event subscriptions can be used for persistence. Review manually.",
                        details={
                            "source": f"WMI {label}",
                            "content": output[:1000],
                        },
                        mitre_id="T1546.003",
                        remediation="Review WMI subscriptions. Remove with: Get-WMIObject -Namespace root\\Subscription -Class __EventConsumer | Remove-WmiObject",
                    )
                    findings.append(finding)
                    print_finding(finding)

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            continue

    return findings


def _scan_appinit_dlls() -> List[Finding]:
    """Check AppInit_DLLs — DLLs injected into every user-mode process."""
    findings = []
    import winreg

    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows"),
    ]

    for hive, subkey in keys:
        try:
            key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)
            try:
                value, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
                load_appinit, _ = winreg.QueryValueEx(key, "LoadAppInit_DLLs")

                if value and str(value).strip() and int(load_appinit) == 1:
                    finding = Finding(
                        module="Persistence Scanner",
                        risk=RiskLevel.HIGH,
                        title=f"AppInit_DLLs persistence detected",
                        description="AppInit_DLLs injects a DLL into every user-mode process. Common malware technique.",
                        details={
                            "source": "Registry: AppInit_DLLs",
                            "dll_path": str(value)[:500],
                            "load_enabled": True,
                        },
                        mitre_id="T1546.010",
                        remediation="Clear AppInit_DLLs value and set LoadAppInit_DLLs to 0 in the registry.",
                    )
                    findings.append(finding)
                    print_finding(finding)
            except OSError:
                pass
            winreg.CloseKey(key)
        except (OSError, PermissionError):
            continue

    return findings


def _scan_ifeo() -> List[Finding]:
    """Check Image File Execution Options — debugger hijacking."""
    findings = []
    import winreg

    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
            0, winreg.KEY_READ
        )
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                sub = winreg.OpenKey(key, subkey_name, 0, winreg.KEY_READ)
                try:
                    debugger, _ = winreg.QueryValueEx(sub, "Debugger")
                    if debugger and str(debugger).strip():
                        debugger_str = str(debugger)
                        # Skip legitimate debuggers
                        safe_debuggers = ["vsjitdebugger", "windbg", "devenv", "ollydbg"]
                        if not any(s in debugger_str.lower() for s in safe_debuggers):
                            finding = Finding(
                                module="Persistence Scanner",
                                risk=RiskLevel.HIGH,
                                title=f"IFEO debugger hijack: {subkey_name}",
                                description=f"Image File Execution Options debugger set for '{subkey_name}'. "
                                            "This redirects program execution to another binary.",
                                details={
                                    "source": "Registry: IFEO",
                                    "target_exe": subkey_name,
                                    "debugger": debugger_str[:500],
                                },
                                mitre_id="T1546.012",
                                remediation=f"Remove the Debugger value from IFEO registry key for '{subkey_name}'.",
                            )
                            findings.append(finding)
                            print_finding(finding)
                except OSError:
                    pass
                winreg.CloseKey(sub)
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except (OSError, PermissionError):
        pass

    return findings


def _scan_winlogon() -> List[Finding]:
    """Check Winlogon Shell, Userinit, and Notify entries."""
    findings = []
    import winreg

    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            0, winreg.KEY_READ
        )

        checks = {
            "Shell": "explorer.exe",
            "Userinit": "c:\\windows\\system32\\userinit.exe",
        }

        for value_name, expected in checks.items():
            try:
                value, _ = winreg.QueryValueEx(key, value_name)
                value_str = str(value).strip().rstrip(",")
                if value_str.lower() != expected.lower():
                    # Check if it starts with the expected value but has additions
                    if expected.lower() in value_str.lower() and len(value_str) > len(expected) + 5:
                        risk = RiskLevel.HIGH
                    elif expected.lower() not in value_str.lower():
                        risk = RiskLevel.CRITICAL
                    else:
                        continue

                    finding = Finding(
                        module="Persistence Scanner",
                        risk=risk,
                        title=f"Winlogon {value_name} modified",
                        description=f"Winlogon {value_name} has been modified from its default value. "
                                    "This runs at every Windows logon.",
                        details={
                            "source": f"Registry: Winlogon\\{value_name}",
                            "current_value": value_str[:500],
                            "expected_value": expected,
                        },
                        mitre_id="T1547.004",
                        remediation=f"Restore Winlogon {value_name} to its default value: '{expected}'.",
                    )
                    findings.append(finding)
                    print_finding(finding)
            except OSError:
                pass

        winreg.CloseKey(key)
    except (OSError, PermissionError):
        pass

    return findings


def _scan_lsa_packages() -> List[Finding]:
    """Check LSA Security Packages for credential interceptors."""
    findings = []
    import winreg

    known_safe = {
        "msv1_0", "tspkg", "wdigest", "kerberos",
        "schannel", "cloudap", "pku2u", "livessp",
        "negotiate", "negoextender", "",
    }

    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            0, winreg.KEY_READ
        )

        for value_name in ("Security Packages", "Authentication Packages"):
            try:
                value, reg_type = winreg.QueryValueEx(key, value_name)
                if isinstance(value, (list, tuple)):
                    packages = [str(p).strip().strip('"').strip("'") for p in value]
                else:
                    packages = [p.strip().strip('"').strip("'") for p in str(value).split("\0")]

                # Filter out empty entries
                packages = [p for p in packages if p]
                unknown = [p for p in packages if p.lower() not in known_safe]
                if unknown:
                    finding = Finding(
                        module="Persistence Scanner",
                        risk=RiskLevel.HIGH,
                        title=f"Unknown LSA {value_name}: {', '.join(unknown)}",
                        description=f"Non-standard packages in LSA {value_name}. Could intercept credentials.",
                        details={
                            "source": f"Registry: LSA\\{value_name}",
                            "unknown_packages": ", ".join(unknown),
                            "all_packages": ", ".join(packages),
                        },
                        mitre_id="T1547.005",
                        remediation=f"Remove unknown packages from LSA {value_name}: {', '.join(unknown)}",
                    )
                    findings.append(finding)
                    print_finding(finding)
            except OSError:
                pass

        winreg.CloseKey(key)
    except (OSError, PermissionError):
        pass

    return findings


def _scan_boot_execute() -> List[Finding]:
    """Check BootExecute for persistence at boot time."""
    findings = []
    import winreg

    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            0, winreg.KEY_READ
        )
        value, _ = winreg.QueryValueEx(key, "BootExecute")

        safe_values = {"autocheck autochk *", ""}
        if isinstance(value, (list, tuple)):
            entries = [v.strip() for v in value if v.strip()]
        else:
            entries = [v.strip() for v in str(value).split("\0") if v.strip()]

        suspicious = [e for e in entries if e.lower() not in safe_values]
        if suspicious:
            finding = Finding(
                module="Persistence Scanner",
                risk=RiskLevel.HIGH,
                title=f"Non-standard BootExecute entries",
                description="BootExecute runs before Windows fully loads. Non-standard entries are suspicious.",
                details={
                    "source": "Registry: Session Manager\\BootExecute",
                    "suspicious_entries": ", ".join(suspicious),
                    "all_entries": ", ".join(entries),
                },
                mitre_id="T1542.003",
                remediation="Remove non-standard entries from BootExecute. Keep only 'autocheck autochk *'.",
            )
            findings.append(finding)
            print_finding(finding)

        winreg.CloseKey(key)
    except (OSError, PermissionError):
        pass

    return findings


def scan() -> List[Finding]:
    """Run the persistence scanner and return findings."""
    print_section("PERSISTENCE SCANNER - Comprehensive Persistence Detection")
    findings = []

    print("  [i] Scanning registry Run keys...")
    findings.extend(_scan_registry())

    print("  [i] Scanning startup folders...")
    findings.extend(_scan_startup_folder())

    print("  [i] Scanning scheduled tasks...")
    findings.extend(_scan_scheduled_tasks())

    print("  [i] Scanning WMI event subscriptions...")
    findings.extend(_scan_wmi_persistence())

    print("  [i] Scanning AppInit_DLLs...")
    findings.extend(_scan_appinit_dlls())

    print("  [i] Scanning Image File Execution Options (IFEO)...")
    findings.extend(_scan_ifeo())

    print("  [i] Scanning Winlogon entries...")
    findings.extend(_scan_winlogon())

    print("  [i] Scanning LSA Security Packages...")
    findings.extend(_scan_lsa_packages())

    print("  [i] Scanning BootExecute entries...")
    findings.extend(_scan_boot_execute())

    print(f"  [i] Persistence scan complete. {len(findings)} findings.")
    return findings

