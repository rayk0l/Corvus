"""
ads_scanner.py - NTFS Alternate Data Streams (ADS) detection module.
Scans user-writable directories for hidden ADS that may conceal:
  1. Executable payloads (PE headers in ADS)
  2. Script-based attacks (PowerShell, VBS, BAT in ADS)
  3. Unusually large ADS (data exfiltration staging)
  4. Mark-of-the-Web (Zone.Identifier) anomalies

MITRE ATT&CK: T1564.004 - Hide Artifacts: NTFS File Attributes
"""

import os
import re
import subprocess
from typing import List, Set

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    is_known_dev_tool, is_os_native_path,
    print_section, print_finding,
)


# Directories to scan for ADS (user-writable, attacker-favored locations)
# Focused on high-risk paths only for performance
SCAN_DIRS = [
    os.path.join(os.environ.get("USERPROFILE", ""), "Desktop"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Downloads"),
    os.path.join(os.environ.get("USERPROFILE", ""), "Documents"),
    os.path.join(os.environ.get("USERPROFILE", ""), "AppData", "Local", "Temp"),
    os.environ.get("PUBLIC", r"C:\Users\Public"),
    os.environ.get("TEMP", r"C:\Windows\Temp"),
]

# Maximum directory depth to scan (shallow for speed)
MAX_DEPTH = 2

# Maximum files per directory to avoid scanning forever
MAX_FILES_PER_DIR = 500

# Safe ADS names that Windows creates normally
SAFE_ADS_NAMES = {
    "zone.identifier",       # Mark-of-the-Web
    "encryptable",           # EFS metadata
    "favicon",               # IE/Edge cache
    "smartscreen",           # Defender SmartScreen
    "{4c8cc155-6c1e-11d1-8e41-00c04fb9386d}",  # Catalog info
}

# Known executable/script extensions inside ADS
EXECUTABLE_ADS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs",
    ".js", ".wsf", ".hta", ".com", ".pif", ".msi",
}

# PE header magic bytes
PE_HEADER_MAGIC = b"MZ"

# Suspicious ADS name patterns
SUSPICIOUS_ADS_PATTERNS = [
    (r"\.exe$", "Executable hidden in ADS", RiskLevel.CRITICAL),
    (r"\.dll$", "DLL hidden in ADS", RiskLevel.CRITICAL),
    (r"\.ps1$", "PowerShell script in ADS", RiskLevel.HIGH),
    (r"\.vbs$", "VBScript in ADS", RiskLevel.HIGH),
    (r"\.bat$|\.cmd$", "Batch script in ADS", RiskLevel.HIGH),
    (r"\.hta$", "HTA file in ADS", RiskLevel.HIGH),
    (r"\.js$|\.wsf$", "Script file in ADS", RiskLevel.HIGH),
    (r"payload|shell|beacon|inject|exploit", "Suspicious ADS name", RiskLevel.HIGH),
]


def _get_ads_for_directory(dirpath: str) -> dict:
    """
    Get all ADS in a directory at once using 'dir /R'.
    Returns dict: {filename_lower: [{'name': stream_name, 'size': size}, ...]}.
    Much faster than per-file scanning.
    """
    results = {}

    try:
        result = subprocess.run(
            ["cmd", "/c", f'dir /R "{dirpath}"'],
            capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace",
        )
        output = result.stdout

        # Parse dir /R output - ADS lines look like:
        #                    123 filename.txt:hidden_stream:$DATA
        for line in output.split("\n"):
            line = line.strip()
            # Match ADS pattern: size  filename:streamname:$DATA
            match = re.search(
                r'(\d+)\s+([^:\s]+):([^:]+):\$DATA',
                line, re.IGNORECASE
            )
            if match:
                size = int(match.group(1))
                filename = match.group(2).strip()
                stream_name = match.group(3).strip()
                filename_lower = filename.lower()

                if filename_lower not in results:
                    results[filename_lower] = []
                results[filename_lower].append({
                    "name": stream_name,
                    "size": size,
                    "filename": filename,
                })

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass

    return results


def _check_ads_content(filepath: str, stream_name: str) -> dict:
    """
    Read the first bytes of an ADS to check for PE headers or script content.
    Returns {'has_pe': bool, 'has_script': bool, 'preview': str}.
    """
    result = {"has_pe": False, "has_script": False, "preview": ""}
    ads_path = f"{filepath}:{stream_name}"

    try:
        # Use PowerShell to read ADS content (cmd can't easily read ADS)
        ps_cmd = f"Get-Content -Path '{ads_path}' -Encoding Byte -TotalCount 64 -ErrorAction SilentlyContinue"
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=5,
            encoding="utf-8", errors="replace"
        )

        if proc.stdout.strip():
            # Parse byte values
            byte_vals = proc.stdout.strip().split()
            raw_bytes = bytes(int(b) for b in byte_vals[:64] if b.isdigit())

            # Check for PE header (MZ)
            if raw_bytes[:2] == PE_HEADER_MAGIC:
                result["has_pe"] = True

            # Check for script indicators
            text_preview = raw_bytes.decode("utf-8", errors="ignore").lower()
            script_indicators = [
                "powershell", "invoke-", "iex ", "downloadstring",
                "wscript", "cscript", "@echo", "dim ", "set ",
                "function ", "var ", "<script", "<?xml",
            ]
            for indicator in script_indicators:
                if indicator in text_preview:
                    result["has_script"] = True
                    break

            result["preview"] = text_preview[:100]

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, ValueError):
        pass

    return result


def _walk_with_depth(base_dir: str, max_depth: int):
    """Walk directories with depth limit."""
    base_depth = base_dir.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, filenames in os.walk(base_dir):
        current_depth = dirpath.rstrip(os.sep).count(os.sep) - base_depth
        if current_depth >= max_depth:
            dirnames.clear()
            continue
        yield dirpath, dirnames, filenames


def scan() -> List[Finding]:
    """Run the ADS scanner and return findings."""
    print_section("ADS SCANNER - Alternate Data Stream Detection")
    findings = []
    scanned_dirs = 0
    ads_found = 0

    # Collect valid scan directories
    dirs_to_scan = [d for d in SCAN_DIRS if os.path.isdir(d)]
    print(f"  [i] Scanning {len(dirs_to_scan)} directories for hidden ADS")

    already_scanned = set()

    for scan_dir in dirs_to_scan:
        try:
            for dirpath, dirnames, filenames in _walk_with_depth(scan_dir, MAX_DEPTH):
                # Skip directories we've already visited (overlapping SCAN_DIRS)
                real_path = os.path.realpath(dirpath)
                if real_path in already_scanned:
                    continue
                already_scanned.add(real_path)

                # Scan entire directory for ADS at once (much faster)
                ads_map = _get_ads_for_directory(dirpath)
                if not ads_map:
                    scanned_dirs += 1
                    continue

                scanned_dirs += 1

                for filename_lower, streams in ads_map.items():
                    for stream in streams:
                        stream_name = stream["name"].lower()
                        stream_size = stream["size"]
                        original_filename = stream["filename"]
                        filepath = os.path.join(dirpath, original_filename)

                        # Skip safe/known ADS names
                        if stream_name in SAFE_ADS_NAMES:
                            continue

                        ads_found += 1

                        # ---- CHECK 1: Suspicious ADS name patterns ----
                        flagged = False
                        for pattern, label, risk in SUSPICIOUS_ADS_PATTERNS:
                            if re.search(pattern, stream_name, re.IGNORECASE):
                                finding = Finding(
                                    module="ADS Scanner",
                                    risk=risk,
                                    title=f"Suspicious ADS: {original_filename}:{stream['name']}",
                                    description=f"{label} detected as alternate data stream.",
                                    details={
                                        "file": filepath,
                                        "ads_name": stream["name"],
                                        "ads_size": f"{stream_size:,} bytes",
                                        "detection": label,
                                    },
                                    mitre_id="T1564.004",
                                    remediation=f"Remove the ADS: powershell Remove-Item -Path '{filepath}:{stream['name']}' -Stream '{stream['name']}'",
                                )
                                findings.append(finding)
                                print_finding(finding)
                                flagged = True
                                break

                        if flagged:
                            continue

                        # ---- CHECK 2: Large ADS (>10KB) - might contain hidden payload ----
                        if stream_size > 10240:
                            # Check content for PE headers
                            content_info = _check_ads_content(filepath, stream["name"])

                            if content_info["has_pe"]:
                                finding = Finding(
                                    module="ADS Scanner",
                                    risk=RiskLevel.CRITICAL,
                                    title=f"PE executable hidden in ADS: {original_filename}:{stream['name']}",
                                    description="A Windows executable (PE file) was found hidden inside an alternate data stream. "
                                                "This is a strong indicator of malware concealment.",
                                    details={
                                        "file": filepath,
                                        "ads_name": stream["name"],
                                        "ads_size": f"{stream_size:,} bytes",
                                        "pe_detected": True,
                                    },
                                    mitre_id="T1564.004",
                                    remediation=f"Delete the file or remove the ADS immediately. Investigate the system for compromise.",
                                )
                                findings.append(finding)
                                print_finding(finding)
                                continue

                            if content_info["has_script"]:
                                finding = Finding(
                                    module="ADS Scanner",
                                    risk=RiskLevel.HIGH,
                                    title=f"Script content in ADS: {original_filename}:{stream['name']}",
                                    description="Script content was detected hidden inside an alternate data stream.",
                                    details={
                                        "file": filepath,
                                        "ads_name": stream["name"],
                                        "ads_size": f"{stream_size:,} bytes",
                                        "content_preview": content_info["preview"][:80],
                                    },
                                    mitre_id="T1564.004",
                                    remediation=f"Remove the ADS and investigate the parent file.",
                                )
                                findings.append(finding)
                                print_finding(finding)
                                continue

                            # Large unknown ADS
                            finding = Finding(
                                module="ADS Scanner",
                                risk=RiskLevel.MEDIUM,
                                title=f"Large ADS detected: {original_filename}:{stream['name']} ({stream_size:,} bytes)",
                                description="A large alternate data stream was found. This may be used to hide data.",
                                details={
                                    "file": filepath,
                                    "ads_name": stream["name"],
                                    "ads_size": f"{stream_size:,} bytes",
                                },
                                mitre_id="T1564.004",
                                remediation=f"Inspect the ADS content: powershell Get-Content -Path '{filepath}:{stream['name']}' -Stream '{stream['name']}'",
                            )
                            findings.append(finding)
                            print_finding(finding)

        except (PermissionError, OSError):
            continue

    print(f"  [i] Scanned {scanned_dirs:,} directories, found {ads_found} non-standard ADS")
    print(f"  [i] ADS scan complete. {len(findings)} findings.")
    return findings
