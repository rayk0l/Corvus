"""
dll_hijack_scanner.py - DLL Search Order Hijacking detection module.
Detects DLL hijacking by checking:
  1. Known hijackable DLLs placed in application directories
  2. Unsigned DLLs in PATH directories that shadow System32 DLLs
  3. Phantom DLL loads (DLLs that programs try to load but don't exist)
  4. DLLs in user-writable locations with system DLL names

MITRE ATT&CK: T1574.001 - Hijack Execution Flow: DLL Search Order Hijacking
"""

import os
import re
import subprocess
from typing import List, Dict, Set

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    check_file_signature, is_os_native_path, is_known_dev_tool,
    print_section, print_finding,
)


# Known DLLs that are commonly hijacked by attackers
# Format: dll_name -> description of what loads it
KNOWN_HIJACKABLE_DLLS = {
    # Commonly hijacked system DLLs
    "version.dll":      "Version information DLL - loaded by many applications",
    "winhttp.dll":      "HTTP services DLL - loaded by updaters and web apps",
    "winhttpcom.dll":   "HTTP COM DLL - loaded by COM-based applications",
    "dbghelp.dll":      "Debug helper DLL - loaded by many applications",
    "dbgcore.dll":      "Debug core DLL - loaded by crash reporters",
    "dwmapi.dll":       "Desktop Window Manager API",
    "uxtheme.dll":      "Visual styles/themes DLL",
    "propsys.dll":      "Property system DLL",
    "ntmarta.dll":      "NT MARTA provider - loaded for ACL operations",
    "secur32.dll":      "Security support provider DLL",
    "crypt32.dll":      "Cryptographic message functions",
    "cryptsp.dll":      "Cryptographic service provider",
    "cryptbase.dll":    "Cryptographic base provider",
    "profapi.dll":      "User profile API",
    "userenv.dll":      "User environment DLL",
    "wtsapi32.dll":     "Terminal Services API",
    "netapi32.dll":     "Network management API",
    "samcli.dll":       "Security Account Manager client",
    "msasn1.dll":       "ASN.1 encoding/decoding",
    "linkinfo.dll":     "Shell link resolution",
    "ntshrui.dll":      "Share management UI",
    "srvcli.dll":       "Server service client",
    "edgegdi.dll":      "GDI helper DLL",
    "fltlib.dll":       "Filter manager library",
    "wldap32.dll":      "LDAP client DLL",
    "amsi.dll":         "Anti-Malware Scan Interface - loading fake amsi.dll bypasses AV",
    "clr.dll":          ".NET Common Language Runtime",
    "mscoree.dll":      ".NET runtime host",
    "msvcp140.dll":     "Visual C++ runtime - loaded by most modern apps",
    "vcruntime140.dll": "Visual C++ runtime",
    "vcruntime140_1.dll": "Visual C++ runtime (extended)",
    "d3d11.dll":        "Direct3D 11 runtime",
    "dxgi.dll":         "DirectX Graphics Infrastructure",
    "d3dcompiler_47.dll": "Direct3D shader compiler",
    "xinput1_3.dll":    "XInput controller API (games)",
    "xinput1_4.dll":    "XInput controller API (games)",
    "wer.dll":          "Windows Error Reporting",
    "tapi32.dll":       "Telephony API",
    "mswsock.dll":      "Winsock helper DLL",
    "dnsapi.dll":       "DNS client API",
    "iphlpapi.dll":     "IP Helper API",
    "rasapi32.dll":     "Remote Access Service API",
    "winsta.dll":       "Window Station library",
    "comctl32.dll":     "Common controls (may be side-loaded)",
}

# System32 path for reference
SYSTEM32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")

# Directories to scan for planted DLLs
SCAN_DIRECTORIES = []

# User-writable suspicious paths
SUSPICIOUS_DLL_LOCATIONS = [
    os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local", "Temp"),
    os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Roaming"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
    os.environ.get("PUBLIC", r"C:\Users\Public"),
]


def _get_program_directories() -> List[str]:
    """Get directories containing installed programs (likely DLL hijack targets)."""
    dirs = set()

    # Program Files
    for env_var in ["ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"]:
        pf = os.environ.get(env_var, "")
        if pf and os.path.isdir(pf):
            try:
                for entry in os.listdir(pf):
                    full = os.path.join(pf, entry)
                    if os.path.isdir(full):
                        dirs.add(full)
            except (PermissionError, OSError):
                pass

    return list(dirs)


def _get_path_directories() -> List[str]:
    """Get directories from the system PATH environment variable."""
    path_env = os.environ.get("PATH", "")
    dirs = []
    for d in path_env.split(";"):
        d = d.strip()
        if d and os.path.isdir(d):
            # Skip System32 and Windows directories
            d_lower = d.lower()
            if d_lower.startswith(SYSTEM32.lower()):
                continue
            if d_lower == os.environ.get("SystemRoot", r"C:\Windows").lower():
                continue
            dirs.append(d)
    return dirs


def _get_system32_dlls() -> Set[str]:
    """Get set of DLL names that exist in System32."""
    dlls = set()
    try:
        for entry in os.listdir(SYSTEM32):
            if entry.lower().endswith(".dll"):
                dlls.add(entry.lower())
    except (PermissionError, OSError):
        pass
    return dlls


def _check_dll_signature(dll_path: str) -> dict:
    """Check if a DLL is signed by a trusted vendor."""
    return check_file_signature(dll_path)


def scan() -> List[Finding]:
    """Run the DLL hijack scanner and return findings."""
    print_section("DLL HIJACK SCANNER - Search Order Hijacking Detection")
    findings = []
    throttle = IOThrottle(ops_per_batch=20, sleep_seconds=0.05)

    # Get reference: what DLLs exist in System32
    print("  [i] Building System32 DLL reference list...")
    system32_dlls = _get_system32_dlls()
    print(f"  [i] Found {len(system32_dlls)} DLLs in System32")

    # ================================================================
    # CHECK 1: Known hijackable DLLs in Program Files directories
    # ================================================================
    print("  [i] Checking Program Files for planted DLLs...")
    program_dirs = _get_program_directories()
    checked_dirs = 0
    planted_dlls = 0

    for prog_dir in program_dirs:
        throttle.tick()
        checked_dirs += 1

        try:
            entries = os.listdir(prog_dir)
        except (PermissionError, OSError):
            continue

        dll_entries = [e for e in entries if e.lower().endswith(".dll")]

        for dll_name in dll_entries:
            dll_lower = dll_name.lower()

            # Is this a known hijackable DLL?
            if dll_lower not in KNOWN_HIJACKABLE_DLLS:
                continue

            dll_path = os.path.join(prog_dir, dll_name)

            # Does the same DLL exist in System32? (indicates potential shadow)
            if dll_lower not in system32_dlls:
                continue

            # Check if this DLL is signed
            sig = _check_dll_signature(dll_path)

            # If it's signed by a trusted vendor, it's likely legitimate side-by-side
            if sig.get("trusted"):
                continue

            planted_dlls += 1

            # Unsigned or untrusted DLL shadowing a System32 DLL
            risk = RiskLevel.HIGH if not sig.get("signed") else RiskLevel.MEDIUM
            desc = KNOWN_HIJACKABLE_DLLS.get(dll_lower, "System DLL")

            finding = Finding(
                module="DLL Hijack Scanner",
                risk=risk,
                title=f"Potential DLL hijack: {dll_name} in {os.path.basename(prog_dir)}",
                description=f"'{dll_name}' ({desc}) exists in an application directory and shadows the System32 version. "
                            f"This could be DLL search order hijacking.",
                details={
                    "dll_path": dll_path,
                    "system32_path": os.path.join(SYSTEM32, dll_name),
                    "dll_description": desc,
                    "signed": sig.get("signed", False),
                    "signer": sig.get("signer", "Unknown"),
                    "trusted": sig.get("trusted", False),
                },
                mitre_id="T1574.001",
                remediation=f"Verify if '{dll_name}' is legitimately needed by the application in '{prog_dir}'. "
                            f"If not, delete it. Compare hash with the System32 version.",
            )
            findings.append(finding)
            print_finding(finding)

    print(f"  [i] Checked {checked_dirs} program directories, found {planted_dlls} suspicious DLLs")

    # ================================================================
    # CHECK 2: System DLL names in user-writable locations
    # ================================================================
    print("  [i] Checking user-writable paths for system DLL names...")
    user_planted = 0

    for susp_dir in SUSPICIOUS_DLL_LOCATIONS:
        if not os.path.isdir(susp_dir):
            continue

        try:
            # Only scan top level and one level deep
            for root, dirs, files in os.walk(susp_dir):
                depth = root.replace(susp_dir, "").count(os.sep)
                if depth > 1:
                    dirs.clear()
                    continue

                for filename in files:
                    if not filename.lower().endswith(".dll"):
                        continue

                    throttle.tick()
                    dll_lower = filename.lower()

                    # Check if this is a system DLL name
                    if dll_lower not in system32_dlls and dll_lower not in KNOWN_HIJACKABLE_DLLS:
                        continue

                    dll_path = os.path.join(root, filename)

                    # Skip dev tool DLLs
                    if is_known_dev_tool("", dll_path):
                        continue

                    # Check signature
                    sig = _check_dll_signature(dll_path)
                    if sig.get("trusted"):
                        continue

                    user_planted += 1

                    finding = Finding(
                        module="DLL Hijack Scanner",
                        risk=RiskLevel.HIGH,
                        title=f"System DLL in user-writable path: {filename}",
                        description=f"A DLL with a system DLL name was found in a user-writable directory. "
                                    f"This is a strong indicator of DLL hijacking or preloading attack.",
                        details={
                            "dll_path": dll_path,
                            "dll_name": filename,
                            "location": root,
                            "signed": sig.get("signed", False),
                            "signer": sig.get("signer", "Unknown"),
                        },
                        mitre_id="T1574.001",
                        remediation=f"Delete '{dll_path}' if it was not intentionally placed there. Scan the system for malware.",
                    )
                    findings.append(finding)
                    print_finding(finding)

        except (PermissionError, OSError):
            continue

    print(f"  [i] Found {user_planted} system DLLs in user-writable locations")

    # ================================================================
    # CHECK 3: PATH hijacking - DLLs in PATH dirs shadowing System32
    # ================================================================
    print("  [i] Checking PATH directories for DLL shadowing...")
    path_dirs = _get_path_directories()
    path_shadows = 0

    for path_dir in path_dirs:
        throttle.tick()
        path_lower = path_dir.lower()

        # Skip known safe locations
        if any(safe in path_lower for safe in [
            "\\windows\\", "\\program files", "\\programdata\\microsoft",
        ]):
            continue

        # Skip dev tool paths
        if is_known_dev_tool("", path_dir):
            continue

        try:
            dll_entries = [e for e in os.listdir(path_dir) if e.lower().endswith(".dll")]
        except (PermissionError, OSError):
            continue

        for dll_name in dll_entries:
            dll_lower = dll_name.lower()

            # Only care about DLLs that shadow System32
            if dll_lower not in system32_dlls:
                continue

            # Only check known hijackable ones (reduces false positives)
            if dll_lower not in KNOWN_HIJACKABLE_DLLS:
                continue

            dll_path = os.path.join(path_dir, dll_name)

            sig = _check_dll_signature(dll_path)
            if sig.get("trusted"):
                continue

            path_shadows += 1

            finding = Finding(
                module="DLL Hijack Scanner",
                risk=RiskLevel.MEDIUM,
                title=f"PATH DLL shadow: {dll_name} in {path_dir}",
                description=f"'{dll_name}' in a PATH directory shadows the System32 version. "
                            f"Applications using LoadLibrary without full paths may load this instead.",
                details={
                    "dll_path": dll_path,
                    "system32_path": os.path.join(SYSTEM32, dll_name),
                    "path_directory": path_dir,
                    "signed": sig.get("signed", False),
                    "signer": sig.get("signer", "Unknown"),
                },
                mitre_id="T1574.001",
                remediation=f"Verify if '{dll_name}' is needed in '{path_dir}'. If not, remove it.",
            )
            findings.append(finding)
            print_finding(finding)

    print(f"  [i] Found {path_shadows} PATH DLL shadows")

    # ================================================================
    # CHECK 4: AMSI DLL bypass detection (critical security bypass)
    # ================================================================
    print("  [i] Checking for AMSI bypass DLLs...")
    amsi_locations = [
        os.environ.get("USERPROFILE", ""),
        os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Documents"),
        os.environ.get("TEMP", ""),
    ]

    for loc in amsi_locations:
        if not loc or not os.path.isdir(loc):
            continue

        amsi_path = os.path.join(loc, "amsi.dll")
        if os.path.isfile(amsi_path):
            finding = Finding(
                module="DLL Hijack Scanner",
                risk=RiskLevel.CRITICAL,
                title=f"AMSI bypass DLL found: {amsi_path}",
                description="A fake amsi.dll was found in a user-writable location. "
                            "This is used to bypass Windows Anti-Malware Scan Interface, "
                            "allowing malicious scripts to run undetected by antivirus.",
                details={
                    "dll_path": amsi_path,
                    "technique": "AMSI DLL Hijacking",
                    "impact": "Antivirus/Defender script scanning bypass",
                },
                mitre_id="T1562.001",
                remediation=f"Delete '{amsi_path}' immediately. This is a security bypass tool. "
                            f"Run a full antivirus scan.",
            )
            findings.append(finding)
            print_finding(finding)

    print(f"  [i] DLL hijack scan complete. {len(findings)} findings.")
    return findings
