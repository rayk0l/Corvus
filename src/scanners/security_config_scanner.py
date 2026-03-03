"""
security_config_scanner.py - Security configuration scanner module.
Checks system security settings: Firewall, Defender, UAC, RDP, SMBv1,
Guest account, AutoPlay, Proxy, BitLocker, Secure Boot, LSASS protection,
Shadow Copies, Password Policy, and Windows Update status.
"""

import subprocess
import re
from typing import List

from scanner_core.utils import Finding, RiskLevel, print_section, print_finding


def _run_cmd(cmd: List[str], timeout: int = 15) -> str:
    """Run a command and return stdout.

    Args:
        cmd: Command as a list of arguments (shell=False for safety).
        timeout: Maximum seconds to wait for the command.
    """
    try:
        result = subprocess.run(
            cmd, shell=False, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace"
        )
        return result.stdout.strip()
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return ""


def _check_firewall() -> List[Finding]:
    """Check Windows Firewall status for all profiles."""
    findings = []
    output = _run_cmd(["netsh", "advfirewall", "show", "allprofiles", "state"])

    if not output:
        return findings

    profiles = {"Domain": False, "Private": False, "Public": False}
    current_profile = ""

    for line in output.split("\n"):
        line = line.strip()
        for profile in profiles:
            if profile.lower() in line.lower() and "profile" in line.lower():
                current_profile = profile
        if "state" in line.lower() and current_profile:
            if "off" in line.lower():
                profiles[current_profile] = True
                current_profile = ""
            else:
                current_profile = ""

    disabled_profiles = [p for p, disabled in profiles.items() if disabled]
    if disabled_profiles:
        risk = RiskLevel.CRITICAL if "Public" in disabled_profiles or len(disabled_profiles) >= 2 else RiskLevel.HIGH
        finding = Finding(
            module="Security Config Scanner",
            risk=risk,
            title=f"Windows Firewall disabled: {', '.join(disabled_profiles)}",
            description="Windows Firewall is disabled for one or more network profiles.",
            details={
                "disabled_profiles": ", ".join(disabled_profiles),
                "recommendation": "Enable Windows Firewall for all profiles",
            },
            mitre_id="T1562.004",
            remediation="Enable Windows Firewall: netsh advfirewall set allprofiles state on",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _check_defender() -> List[Finding]:
    """Check Windows Defender real-time protection status."""
    findings = []

    output = _run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Get-MpPreference | Select-Object "
        "DisableRealtimeMonitoring, DisableIOAVProtection, DisableBehaviorMonitoring, "
        "DisableBlockAtFirstSeen, DisableScriptScanning | Format-List"
    ])

    if not output:
        return findings

    checks = {
        "DisableRealtimeMonitoring": ("Real-time Protection disabled", RiskLevel.CRITICAL),
        "DisableIOAVProtection": ("IOAV Protection disabled", RiskLevel.HIGH),
        "DisableBehaviorMonitoring": ("Behavior Monitoring disabled", RiskLevel.HIGH),
        "DisableScriptScanning": ("Script Scanning disabled", RiskLevel.MEDIUM),
    }

    for key, (label, risk) in checks.items():
        pattern = rf"{key}\s*:\s*True"
        if re.search(pattern, output, re.IGNORECASE):
            finding = Finding(
                module="Security Config Scanner",
                risk=risk,
                title=f"Windows Defender: {label}",
                description=f"{label}. The system is vulnerable to malware.",
                details={
                    "setting": key,
                    "value": "True (Disabled)",
                    "recommendation": f"Enable {label} via Windows Security settings",
                },
                mitre_id="T1562.001",
                remediation=f"Re-enable {label} via Windows Security settings or PowerShell: Set-MpPreference -{key} $false",
            )
            findings.append(finding)
            print_finding(finding)

    # Check for exclusions
    excl_output = _run_cmd([
        "powershell", "-NoProfile", "-Command",
        "Get-MpPreference | Select-Object "
        "ExclusionPath, ExclusionProcess, ExclusionExtension | Format-List"
    ])
    if excl_output:
        for line in excl_output.split("\n"):
            if "ExclusionPath" in line and ":" in line:
                paths = line.split(":", 1)[1].strip()
                if paths and paths != "{}":
                    finding = Finding(
                        module="Security Config Scanner",
                        risk=RiskLevel.MEDIUM,
                        title="Windows Defender path exclusions detected",
                        description="Excluded paths may hide malware from scanning.",
                        details={
                            "excluded_paths": paths[:500],
                            "recommendation": "Review exclusions and remove unnecessary entries",
                        },
                        mitre_id="T1562.001",
                        remediation="Review and remove unnecessary Defender exclusions: Get-MpPreference | Select ExclusionPath",
                    )
                    findings.append(finding)
                    print_finding(finding)
                    break

    return findings


def _check_uac() -> List[Finding]:
    """Check UAC (User Account Control) status."""
    findings = []
    output = _run_cmd([
        "reg", "query",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "/v", "EnableLUA"
    ])
    if "0x0" in output:
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.HIGH,
            title="UAC (User Account Control) is disabled",
            description="UAC is disabled, allowing applications to run with elevated privileges without prompting.",
            details={
                "setting": "EnableLUA",
                "value": "0 (Disabled)",
                "recommendation": "Enable UAC via Control Panel > User Account Control Settings",
            },
            mitre_id="T1548.002",
            remediation="Enable UAC: reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DWORD /d 1 /f",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _check_rdp() -> List[Finding]:
    """Check RDP configuration."""
    findings = []

    # Check if RDP is enabled
    rdp_output = _run_cmd([
        "reg", "query",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server",
        "/v", "fDenyTSConnections"
    ])
    rdp_enabled = "0x0" in rdp_output

    if rdp_enabled:
        # Check NLA
        nla_output = _run_cmd([
            "reg", "query",
            r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp",
            "/v", "UserAuthentication"
        ])
        nla_disabled = "0x0" in nla_output

        if nla_disabled:
            finding = Finding(
                module="Security Config Scanner",
                risk=RiskLevel.HIGH,
                title="RDP enabled without Network Level Authentication (NLA)",
                description="RDP is accessible without NLA, making it vulnerable to brute force and exploitation.",
                details={
                    "rdp_enabled": True,
                    "nla_enabled": False,
                    "recommendation": "Enable NLA for RDP connections or disable RDP if not needed",
                },
                mitre_id="T1021.001",
                remediation="Enable NLA for RDP or disable RDP if not needed.",
            )
            findings.append(finding)
            print_finding(finding)

    return findings


def _check_smbv1() -> List[Finding]:
    """Check if SMBv1 is enabled."""
    findings = []

    output = _run_cmd([
        "powershell", "-NoProfile", "-Command",
        "(Get-SmbServerConfiguration).EnableSMB1Protocol"
    ])

    if "true" in output.lower():
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.HIGH,
            title="SMBv1 protocol is enabled",
            description="SMBv1 is vulnerable to EternalBlue (CVE-2017-0144). Used by WannaCry and NotPetya.",
            details={
                "protocol": "SMBv1",
                "status": "Enabled",
                "cve": "CVE-2017-0144 (EternalBlue)",
                "recommendation": "Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false",
            },
            mitre_id="T1210",
            remediation="Disable SMBv1: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _check_guest_account() -> List[Finding]:
    """Check if the Guest account is active."""
    findings = []
    output = _run_cmd(["net", "user", "Guest"])

    if output and "active" in output.lower():
        for line in output.split("\n"):
            if "active" in line.lower() and "yes" in line.lower():
                finding = Finding(
                    module="Security Config Scanner",
                    risk=RiskLevel.MEDIUM,
                    title="Guest account is active",
                    description="The Guest account is enabled, allowing unauthenticated access.",
                    details={
                        "account": "Guest",
                        "status": "Active",
                        "recommendation": "Disable the Guest account: net user Guest /active:no",
                    },
                    mitre_id="T1078.001",
                    remediation="Disable the Guest account: net user Guest /active:no",
                )
                findings.append(finding)
                print_finding(finding)
                break

    return findings


def _check_autorun() -> List[Finding]:
    """Check if AutoRun/AutoPlay is enabled."""
    findings = []
    output = _run_cmd([
        "reg", "query",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
        "/v", "NoDriveTypeAutoRun"
    ])

    # If the key doesn't exist or value is 0, AutoRun is enabled
    if "NoDriveTypeAutoRun" not in output or "0x0" in output:
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.MEDIUM,
            title="AutoRun/AutoPlay may be enabled",
            description="AutoRun can automatically execute malware from removable media.",
            details={
                "recommendation": "Disable AutoRun via Group Policy or registry",
            },
            mitre_id="T1091",
            remediation="Disable AutoRun: reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer /v NoDriveTypeAutoRun /t REG_DWORD /d 0xFF /f",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _check_proxy() -> List[Finding]:
    """Check system proxy settings for potential traffic interception."""
    findings = []

    # Check IE/system proxy via registry
    output = _run_cmd([
        "reg", "query",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        "/v", "ProxyEnable"
    ])
    proxy_enabled = "0x1" in output

    if proxy_enabled:
        proxy_server = ""
        server_output = _run_cmd([
            "reg", "query",
            r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            "/v", "ProxyServer"
        ])
        for line in server_output.split("\n"):
            if "ProxyServer" in line and "REG_SZ" in line:
                proxy_server = line.split("REG_SZ")[-1].strip()

        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.MEDIUM,
            title=f"System proxy configured: {proxy_server or 'Unknown'}",
            description="A system-wide proxy is configured. Verify this is intentional. "
                        "Malware can set proxies to intercept traffic.",
            details={
                "proxy_enabled": True,
                "proxy_server": proxy_server or "Unknown",
                "recommendation": "Verify the proxy configuration is legitimate and intended",
            },
            mitre_id="T1090",
            remediation="If unexpected, disable the proxy: Internet Options → Connections → LAN Settings → Uncheck proxy.",
        )
        findings.append(finding)
        print_finding(finding)

    # Check environment variable proxies
    for env_var in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        import os
        proxy_val = os.environ.get(env_var, "")
        if proxy_val:
            finding = Finding(
                module="Security Config Scanner",
                risk=RiskLevel.MEDIUM,
                title=f"Environment proxy: {env_var}={proxy_val[:80]}",
                description=f"Environment variable {env_var} is set. Verify this is intentional.",
                details={
                    "variable": env_var,
                    "value": proxy_val[:200],
                    "recommendation": "Remove if not intentionally configured",
                },
                mitre_id="T1090",
            )
            findings.append(finding)
            print_finding(finding)

    return findings


def _check_bitlocker() -> List[Finding]:
    """Check BitLocker disk encryption status."""
    findings = []

    output = _run_cmd(
        [
            "powershell", "-NoProfile", "-Command",
            "Get-BitLockerVolume -MountPoint C: 2>$null | "
            "Select-Object -Property MountPoint, VolumeStatus, ProtectionStatus, EncryptionMethod | Format-List"
        ],
        timeout=20
    )

    if not output or "not recognized" in output.lower():
        # BitLocker cmdlet not available (Home edition)
        output = _run_cmd(["manage-bde", "-status", "C:"], timeout=15)
        if output:
            if "Fully Decrypted" in output or "Protection Off" in output:
                finding = Finding(
                    module="Security Config Scanner",
                    risk=RiskLevel.MEDIUM,
                    title="BitLocker: System drive (C:) is NOT encrypted",
                    description="The system drive is not encrypted with BitLocker. "
                                "Data can be accessed if the device is stolen.",
                    details={
                        "drive": "C:",
                        "status": "Not Encrypted",
                        "recommendation": "Enable BitLocker on the system drive",
                    },
                    mitre_id="T1005",
                    remediation="Enable BitLocker: Control Panel → System and Security → BitLocker Drive Encryption.",
                )
                findings.append(finding)
                print_finding(finding)
        return findings

    if "FullyDecrypted" in output or "Off" in output:
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.MEDIUM,
            title="BitLocker: System drive (C:) is NOT encrypted",
            description="The system drive is not encrypted with BitLocker.",
            details={
                "drive": "C:",
                "status": "Not Encrypted / Protection Off",
                "recommendation": "Enable BitLocker on the system drive",
            },
            mitre_id="T1005",
            remediation="Enable BitLocker: Control Panel → System and Security → BitLocker Drive Encryption.",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _check_secure_boot() -> List[Finding]:
    """Check Secure Boot status."""
    findings = []

    output = _run_cmd(
        ["powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI 2>$null"],
        timeout=10
    )

    if "false" in output.lower():
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.MEDIUM,
            title="Secure Boot is DISABLED",
            description="Secure Boot is disabled. This allows unsigned bootloaders and rootkits to load at boot time.",
            details={
                "status": "Disabled",
                "recommendation": "Enable Secure Boot in UEFI/BIOS settings",
            },
            mitre_id="T1542",
            remediation="Enter BIOS/UEFI settings and enable Secure Boot.",
        )
        findings.append(finding)
        print_finding(finding)
    elif "not supported" in output.lower() or "cmdlet" in output.lower():
        # Legacy BIOS — no Secure Boot possible
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.INFO,
            title="Secure Boot: Not available (Legacy BIOS)",
            description="This system uses Legacy BIOS which does not support Secure Boot.",
            details={
                "status": "Not Available",
                "boot_mode": "Legacy BIOS",
            },
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _check_lsass_protection() -> List[Finding]:
    """Check LSASS RunAsPPL (Protected Process Light) status."""
    findings = []

    output = _run_cmd([
        "reg", "query",
        r"HKLM\SYSTEM\CurrentControlSet\Control\Lsa",
        "/v", "RunAsPPL"
    ])

    if "RunAsPPL" not in output or "0x0" in output:
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.HIGH,
            title="LSASS protection (RunAsPPL) is NOT enabled",
            description="LSASS process is not running as Protected Process Light. "
                        "This makes credential dumping tools like Mimikatz effective.",
            details={
                "setting": "RunAsPPL",
                "value": "Not Enabled",
                "recommendation": "Enable LSASS protection: "
                    "reg add HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa /v RunAsPPL /t REG_DWORD /d 1 /f",
            },
            mitre_id="T1003.001",
            remediation="Enable LSASS protection: Set RunAsPPL to 1 in registry under HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _check_shadow_copies() -> List[Finding]:
    """Check Volume Shadow Copy status (ransomware indicator if deleted)."""
    findings = []

    # Check VSS service status
    vss_output = _run_cmd(["sc", "query", "VSS"])
    vss_running = "RUNNING" in vss_output

    # Check for existing shadow copies
    shadow_output = _run_cmd(["vssadmin", "list", "shadows"], timeout=20)

    has_shadows = "Shadow Copy ID" in shadow_output or "shadow copy" in shadow_output.lower()
    no_shadows = "No items found" in shadow_output or not shadow_output.strip()

    if no_shadows:
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.MEDIUM,
            title="No Volume Shadow Copies found",
            description="No shadow copies exist on the system. Shadow copies provide "
                        "recovery points. Ransomware deletes shadow copies to prevent recovery.",
            details={
                "vss_service": "Running" if vss_running else "Stopped",
                "shadow_copies": "None",
                "recommendation": "Verify shadow copies are being created. "
                    "Enable System Restore or configure backup schedules.",
            },
            mitre_id="T1490",
            remediation="Enable System Protection: System Properties → System Protection → Configure → Turn on.",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _check_password_policy() -> List[Finding]:
    """Check password policy settings."""
    findings = []

    output = _run_cmd(["net", "accounts"])
    if not output:
        return findings

    # Parse key values
    min_length = 0
    max_age = 0
    lockout_threshold = 0

    for line in output.split("\n"):
        line_lower = line.lower().strip()
        if "minimum password length" in line_lower or "en az parola uzunlu" in line_lower:
            match = re.search(r"(\d+)", line)
            if match:
                min_length = int(match.group(1))
        elif "maximum password age" in line_lower or "en fazla parola ya" in line_lower:
            match = re.search(r"(\d+)", line)
            if match:
                max_age = int(match.group(1))
        elif "lockout threshold" in line_lower or "kilitleme e" in line_lower:
            match = re.search(r"(\d+)", line)
            if match:
                lockout_threshold = int(match.group(1))

    if min_length < 8:
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.MEDIUM,
            title=f"Weak password policy: minimum length is {min_length}",
            description="Password minimum length is below recommended 8 characters.",
            details={
                "current_min_length": min_length,
                "recommended": "8 or more characters",
                "recommendation": "Set minimum password length: net accounts /minpwlen:8",
            },
            mitre_id="T1110",
            remediation="Increase minimum password length: net accounts /minpwlen:8",
        )
        findings.append(finding)
        print_finding(finding)

    if lockout_threshold == 0:
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.MEDIUM,
            title="Account lockout is DISABLED",
            description="No account lockout threshold is set. Brute force attacks have unlimited attempts.",
            details={
                "lockout_threshold": "Never (0)",
                "recommended": "5-10 attempts",
                "recommendation": "Set lockout threshold: net accounts /lockoutthreshold:5",
            },
            mitre_id="T1110",
            remediation="Enable account lockout: net accounts /lockoutthreshold:5",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def _check_windows_update() -> List[Finding]:
    """Check when Windows Update was last run."""
    findings = []

    output = _run_cmd(
        [
            "powershell", "-NoProfile", "-Command",
            "$s = New-Object -ComObject Microsoft.Update.AutoUpdate; "
            "$s.Results | Select-Object LastSearchSuccessDate, LastInstallationSuccessDate | Format-List"
        ],
        timeout=20
    )

    if output and "LastInstallation" in output:
        import re
        from datetime import datetime, timedelta
        match = re.search(r"LastInstallationSuccessDate\s*:\s*(.+)", output)
        if match:
            date_str = match.group(1).strip()
            try:
                # Try common date format
                last_update = datetime.strptime(date_str[:10], "%m/%d/%Y")
                days_ago = (datetime.now() - last_update).days
                if days_ago > 60:
                    finding = Finding(
                        module="Security Config Scanner",
                        risk=RiskLevel.HIGH if days_ago > 90 else RiskLevel.MEDIUM,
                        title=f"Windows Update: Last install was {days_ago} days ago",
                        description=f"The last successful Windows Update installation was {days_ago} days ago. "
                                    "Unpatched systems are vulnerable to known exploits.",
                        details={
                            "last_update": date_str,
                            "days_since_update": days_ago,
                            "recommendation": "Run Windows Update immediately",
                        },
                        mitre_id="T1190",
                        remediation="Run Windows Update: Settings → Update & Security → Windows Update → Check for updates.",
                    )
                    findings.append(finding)
                    print_finding(finding)
            except (ValueError, IndexError):
                pass

    return findings


def _check_credential_guard() -> List[Finding]:
    """Check if Credential Guard is enabled."""
    findings = []

    output = _run_cmd([
        "reg", "query",
        r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
        "/v", "EnableVirtualizationBasedSecurity"
    ])

    vbs_enabled = "0x1" in output

    if not vbs_enabled:
        finding = Finding(
            module="Security Config Scanner",
            risk=RiskLevel.INFO,
            title="Credential Guard / VBS is not enabled",
            description="Virtualization-Based Security (VBS) and Credential Guard are not enabled. "
                        "These features protect credentials from memory-based attacks.",
            details={
                "vbs_status": "Not Enabled",
                "recommendation": "Enable via Group Policy or Device Guard settings",
            },
            mitre_id="T1003",
            remediation="Enable VBS: Group Policy → Computer Config → Admin Templates → System → Device Guard → "
                        "Turn On Virtualization Based Security.",
        )
        findings.append(finding)
        print_finding(finding)

    return findings


def scan() -> List[Finding]:
    """Run the security configuration scanner and return findings."""
    print_section("SECURITY CONFIG SCANNER - System Hardening Checks")
    findings = []

    print("  [i] Checking Windows Firewall...")
    findings.extend(_check_firewall())

    print("  [i] Checking Windows Defender...")
    findings.extend(_check_defender())

    print("  [i] Checking UAC settings...")
    findings.extend(_check_uac())

    print("  [i] Checking RDP configuration...")
    findings.extend(_check_rdp())

    print("  [i] Checking SMBv1 protocol...")
    findings.extend(_check_smbv1())

    print("  [i] Checking Guest account...")
    findings.extend(_check_guest_account())

    print("  [i] Checking AutoRun settings...")
    findings.extend(_check_autorun())

    print("  [i] Checking proxy settings...")
    findings.extend(_check_proxy())

    print("  [i] Checking BitLocker encryption...")
    findings.extend(_check_bitlocker())

    print("  [i] Checking Secure Boot status...")
    findings.extend(_check_secure_boot())

    print("  [i] Checking LSASS protection (RunAsPPL)...")
    findings.extend(_check_lsass_protection())

    print("  [i] Checking Volume Shadow Copies...")
    findings.extend(_check_shadow_copies())

    print("  [i] Checking password policy...")
    findings.extend(_check_password_policy())

    print("  [i] Checking Windows Update status...")
    findings.extend(_check_windows_update())

    print("  [i] Checking Credential Guard / VBS...")
    findings.extend(_check_credential_guard())

    print(f"  [i] Security config scan complete. {len(findings)} findings.")
    return findings
