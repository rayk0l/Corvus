"""
attack_vector_scanner.py - Modern attack vector file extension scanner.

Detects dangerous file types in user-writable directories that are commonly
used in initial access attacks:

  - .lnk   -> Shortcut files targeting PowerShell/cmd/mshta  (T1204.002)
  - .iso    -> Disk images bypassing MOTW                     (T1553.005)
  - .img    -> Disk images bypassing MOTW                     (T1553.005)
  - .vhd    -> Virtual hard disks bypassing MOTW              (T1553.005)
  - .vhdx   -> Virtual hard disks bypassing MOTW              (T1553.005)
  - .chm    -> Compiled HTML Help executing scripts           (T1218.001)
  - .xll    -> Excel add-ins for code execution               (T1137.006)

This module is LIGHTWEIGHT — NOT in HEAVY_MODULES.  It runs in all scan
modes including --quick.  It only scans user-writable directories to a
shallow depth and never reads file content (except small .lnk headers).
"""

import os
import re
import glob
import struct
from typing import List, Optional, Dict, Tuple
from datetime import datetime

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    print_section, print_finding,
)


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Dangerous extensions and their metadata
DANGEROUS_EXTENSIONS: Dict[str, Dict] = {
    ".lnk": {
        "name": "Windows Shortcut",
        "mitre": "T1204.002",
        "description": "Shortcut files can execute arbitrary commands",
    },
    ".iso": {
        "name": "Disk Image (ISO)",
        "mitre": "T1553.005",
        "description": "Disk images bypass Mark of the Web protection",
    },
    ".img": {
        "name": "Disk Image (IMG)",
        "mitre": "T1553.005",
        "description": "Disk images bypass Mark of the Web protection",
    },
    ".vhd": {
        "name": "Virtual Hard Disk",
        "mitre": "T1553.005",
        "description": "Virtual hard disks bypass Mark of the Web protection",
    },
    ".vhdx": {
        "name": "Virtual Hard Disk (VHDX)",
        "mitre": "T1553.005",
        "description": "Virtual hard disks bypass Mark of the Web protection",
    },
    ".chm": {
        "name": "Compiled HTML Help",
        "mitre": "T1218.001",
        "description": "CHM files can execute embedded scripts and ActiveX",
    },
    ".xll": {
        "name": "Excel Add-In (XLL)",
        "mitre": "T1137.006",
        "description": "XLL add-ins execute native code when loaded by Excel",
    },
}

TARGET_EXTENSIONS = set(DANGEROUS_EXTENSIONS.keys())

# User-writable directories to scan (glob patterns)
_SYSDRIVE = os.environ.get("SystemDrive", "C:")

USER_WRITABLE_PATTERNS = [
    os.path.join(_SYSDRIVE, "\\Users\\*\\Downloads"),
    os.path.join(_SYSDRIVE, "\\Users\\*\\Desktop"),
    os.path.join(_SYSDRIVE, "\\Users\\*\\Documents"),
    os.path.join(_SYSDRIVE, "\\Users\\*\\AppData\\Local\\Temp"),
    os.path.join(_SYSDRIVE, "\\Users\\*\\AppData\\Roaming"),
    os.path.join(_SYSDRIVE, "\\Users\\Public"),
    os.path.join(_SYSDRIVE, "\\Windows\\Temp"),
]

# Directories that indicate high-risk context (temp/staging areas)
_HIGH_RISK_DIR_MARKERS = ("\\temp", "\\tmp", "\\appdata", "\\public")

# Max traversal depth (shallow — targeted user dirs only)
MAX_DEPTH = 5

# Max .lnk file size to parse (256 KB — lnk files are small)
MAX_LNK_SIZE = 256 * 1024

# Directories to skip during walk
_SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".venv", "venv",
    "site-packages", "$recycle.bin",
}


# ---------------------------------------------------------------------------
# .lnk Suspicious Target Detection
# ---------------------------------------------------------------------------

# Process names that are suspicious when targeted by a .lnk
SUSPICIOUS_LNK_TARGETS = {
    "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "cmd.exe", "cmd",
    "mshta.exe", "mshta",
    "wscript.exe", "wscript",
    "cscript.exe", "cscript",
    "certutil.exe", "certutil",
    "rundll32.exe", "rundll32",
    "regsvr32.exe", "regsvr32",
    "bitsadmin.exe", "bitsadmin",
}

# Patterns in .lnk target+arguments that indicate abuse
_LNK_SUSPICIOUS_PATTERNS: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"powershell.*-enc", re.IGNORECASE),
     "PowerShell encoded command"),
    (re.compile(r"powershell.*-w\s*hidden", re.IGNORECASE),
     "PowerShell hidden window"),
    (re.compile(r"IEX\s*\(", re.IGNORECASE),
     "PowerShell Invoke-Expression"),
    (re.compile(r"downloadstring", re.IGNORECASE),
     "PowerShell download cradle"),
    (re.compile(r"frombase64string", re.IGNORECASE),
     "Base64 decoding"),
    (re.compile(r"cmd\.exe\s*/c\s", re.IGNORECASE),
     "cmd.exe command execution"),
    (re.compile(r"mshta(?:\.exe)?\s+(javascript|vbscript|http)", re.IGNORECASE),
     "mshta script/URL execution"),
    (re.compile(r"certutil.*(-urlcache|-decode|-encode)", re.IGNORECASE),
     "certutil abuse"),
    (re.compile(r"regsvr32.*/s.*/i:", re.IGNORECASE),
     "regsvr32 COM scriptlet loading"),
    (re.compile(r"bitsadmin.*/transfer", re.IGNORECASE),
     "BITS transfer abuse"),
]


# ---------------------------------------------------------------------------
# .lnk Binary Parser (MS-SHLLINK format)
# ---------------------------------------------------------------------------

# Shell Link Header constants
_LNK_HEADER_SIZE = 0x4C
_LNK_CLSID = (
    b'\x01\x14\x02\x00\x00\x00\x00\x00'
    b'\xc0\x00\x00\x00\x00\x00\x00\x46'
)

# LinkFlags bit positions
_HAS_LINK_TARGET_ID_LIST = 0x00000001
_HAS_LINK_INFO = 0x00000002
_HAS_NAME = 0x00000004
_HAS_RELATIVE_PATH = 0x00000008
_HAS_WORKING_DIR = 0x00000010
_HAS_ARGUMENTS = 0x00000020
_HAS_ICON_LOCATION = 0x00000040
_IS_UNICODE = 0x00000080


def _parse_lnk(filepath: str) -> Optional[Dict[str, str]]:
    """Parse a .lnk shortcut file and extract target path and arguments.

    Uses the Shell Link Binary File Format specification (MS-SHLLINK).

    Args:
        filepath: Path to the .lnk file.

    Returns:
        Dict with keys: target_path, arguments, working_dir, icon_location.
        Returns None if the file is not a valid .lnk or cannot be parsed.
    """
    try:
        fsize = os.path.getsize(filepath)
        if fsize < _LNK_HEADER_SIZE or fsize > MAX_LNK_SIZE:
            return None

        with open(filepath, "rb") as f:
            data = f.read(MAX_LNK_SIZE)
    except (PermissionError, OSError):
        return None

    return _parse_lnk_bytes(data)


def _parse_lnk_bytes(data: bytes) -> Optional[Dict[str, str]]:
    """Parse raw .lnk binary data. Separated for testability.

    Args:
        data: Raw bytes of a .lnk file.

    Returns:
        Dict with target_path, arguments, working_dir, icon_location
        or None if invalid.
    """
    if len(data) < _LNK_HEADER_SIZE:
        return None

    # Validate header size
    header_size = struct.unpack_from("<I", data, 0)[0]
    if header_size != _LNK_HEADER_SIZE:
        return None

    # Validate CLSID
    clsid = data[4:20]
    if clsid != _LNK_CLSID:
        return None

    # Read LinkFlags
    link_flags = struct.unpack_from("<I", data, 20)[0]
    is_unicode = bool(link_flags & _IS_UNICODE)

    result: Dict[str, str] = {
        "target_path": "",
        "arguments": "",
        "working_dir": "",
        "icon_location": "",
    }

    offset = _LNK_HEADER_SIZE

    # --- Skip LinkTargetIDList if present ---
    if link_flags & _HAS_LINK_TARGET_ID_LIST:
        if offset + 2 > len(data):
            return result
        id_list_size = struct.unpack_from("<H", data, offset)[0]
        offset += 2 + id_list_size

    # --- Parse LinkInfo if present (contains local base path) ---
    if link_flags & _HAS_LINK_INFO:
        if offset + 4 > len(data):
            return result
        link_info_size = struct.unpack_from("<I", data, offset)[0]

        if link_info_size >= 28 and offset + 28 <= len(data):
            link_info_header_size = struct.unpack_from("<I", data, offset + 4)[0]
            link_info_flags = struct.unpack_from("<I", data, offset + 8)[0]

            # VolumeIDAndLocalBasePath flag
            if link_info_flags & 0x00000001:
                local_base_path_offset = struct.unpack_from(
                    "<I", data, offset + 16,
                )[0]
                abs_offset = offset + local_base_path_offset
                if abs_offset < len(data):
                    end = data.find(b'\x00', abs_offset)
                    if end == -1:
                        end = min(abs_offset + 260, len(data))
                    try:
                        result["target_path"] = data[abs_offset:end].decode(
                            "ascii", errors="replace",
                        )
                    except Exception:
                        pass

                # Check for LocalBasePathUnicode (header size >= 0x24 = 36)
                if link_info_header_size >= 0x24 and offset + 32 <= len(data):
                    try:
                        unicode_offset = struct.unpack_from(
                            "<I", data, offset + 28,
                        )[0]
                        abs_u = offset + unicode_offset
                        if abs_u < len(data):
                            # Find UTF-16 null terminator (two consecutive zeros
                            # on an even boundary)
                            end_u = abs_u
                            while end_u + 1 < len(data):
                                if data[end_u] == 0 and data[end_u + 1] == 0:
                                    break
                                end_u += 2
                            path_bytes = data[abs_u:end_u]
                            if path_bytes:
                                result["target_path"] = path_bytes.decode(
                                    "utf-16-le", errors="replace",
                                ).rstrip('\x00')
                    except Exception:
                        pass

        offset += link_info_size

    # --- Parse StringData sections (order defined by spec) ---
    string_fields: List[str] = []
    if link_flags & _HAS_NAME:
        string_fields.append("name")
    if link_flags & _HAS_RELATIVE_PATH:
        string_fields.append("relative_path")
    if link_flags & _HAS_WORKING_DIR:
        string_fields.append("working_dir")
    if link_flags & _HAS_ARGUMENTS:
        string_fields.append("arguments")
    if link_flags & _HAS_ICON_LOCATION:
        string_fields.append("icon_location")

    for field in string_fields:
        if offset + 2 > len(data):
            break
        count = struct.unpack_from("<H", data, offset)[0]
        offset += 2

        byte_count = count * 2 if is_unicode else count
        if offset + byte_count > len(data):
            break

        raw = data[offset:offset + byte_count]
        offset += byte_count

        try:
            if is_unicode:
                text = raw.decode("utf-16-le", errors="replace").rstrip('\x00')
            else:
                text = raw.decode("ascii", errors="replace").rstrip('\x00')
        except Exception:
            text = ""

        if field == "relative_path" and not result["target_path"]:
            result["target_path"] = text
        elif field == "arguments":
            result["arguments"] = text
        elif field == "working_dir":
            result["working_dir"] = text
        elif field == "icon_location":
            result["icon_location"] = text

    return result


# ---------------------------------------------------------------------------
# File Collection
# ---------------------------------------------------------------------------

def _resolve_scan_dirs() -> List[str]:
    """Resolve user-writable directories from glob patterns."""
    resolved = []
    for pattern in USER_WRITABLE_PATTERNS:
        if "*" in pattern:
            resolved.extend(glob.glob(pattern))
        elif os.path.isdir(pattern):
            resolved.append(pattern)
    return list(set(resolved))


def _collect_dangerous_files(
    directories: List[str],
    throttle: IOThrottle,
) -> List[Tuple[str, str]]:
    """Walk directories and collect files with dangerous extensions.

    Args:
        directories: List of directory paths to scan.
        throttle: IOThrottle instance for disk-friendly scanning.

    Returns:
        List of (filepath, extension) tuples.
    """
    files: List[Tuple[str, str]] = []
    scanned_dirs: set = set()

    for dir_path in directories:
        dir_norm = os.path.normpath(dir_path).lower()
        if dir_norm in scanned_dirs:
            continue
        scanned_dirs.add(dir_norm)

        try:
            for root, dirs, filenames in os.walk(dir_path):
                depth = root.replace(dir_path, "").count(os.sep)
                if depth > MAX_DEPTH:
                    dirs.clear()
                    continue

                # Skip known non-useful dirs
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in _SKIP_DIRS
                ]

                for fname in filenames:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in TARGET_EXTENSIONS:
                        full_path = os.path.join(root, fname)
                        files.append((full_path, ext))
                    throttle.tick()
        except (PermissionError, OSError):
            continue

    return files


# ---------------------------------------------------------------------------
# Analysis Functions
# ---------------------------------------------------------------------------

def _is_high_risk_location(filepath: str) -> bool:
    """Check if a file path is in a high-risk staging location (Temp, AppData, Public)."""
    path_lower = filepath.lower()
    return any(marker in path_lower for marker in _HIGH_RISK_DIR_MARKERS)


def _safe_filesize(filepath: str) -> str:
    """Get human-readable file size string."""
    try:
        size = os.path.getsize(filepath)
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    except OSError:
        return "Unknown"


def _safe_ctime(filepath: str) -> str:
    """Get file creation time as string."""
    try:
        ctime = os.path.getctime(filepath)
        return datetime.fromtimestamp(ctime).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        return "Unknown"


def _analyze_lnk_data(
    lnk_data: Dict[str, str],
    filepath: str,
) -> Optional[Finding]:
    """Analyze parsed .lnk data for suspicious targets and arguments.

    Separated from file I/O for testability. Checks the target/arguments
    against known suspicious patterns (LOLBins, scripts, encoders).

    Args:
        lnk_data: Dict from _parse_lnk / _parse_lnk_bytes with keys
                  target_path, arguments, working_dir, icon_location.
        filepath: Original .lnk file path (for Finding details).

    Returns:
        Finding if suspicious, None if benign.
    """
    target = lnk_data.get("target_path", "")
    arguments = lnk_data.get("arguments", "")
    basename = os.path.basename(filepath)

    # Combine target + args for pattern matching
    full_command = f"{target} {arguments}".strip()
    if not full_command:
        return None

    # Check if target is a suspicious executable
    target_name = os.path.basename(target).lower() if target else ""
    is_suspicious_target = target_name in SUSPICIOUS_LNK_TARGETS

    # Check for suspicious patterns in the full command
    matched_patterns: List[str] = []
    for pattern, desc in _LNK_SUSPICIOUS_PATTERNS:
        if pattern.search(full_command):
            matched_patterns.append(desc)

    if not is_suspicious_target and not matched_patterns:
        return None

    # Bare interpreter shortcut with no suspicious arguments or patterns
    # is a normal OS shortcut (e.g., PowerShell.lnk → powershell.exe)
    if is_suspicious_target and not matched_patterns:
        args_stripped = arguments.strip()
        if not args_stripped:
            return None
        # Developer tool shortcuts that launch via cmd/powershell are
        # legitimate (Claude Code, npm scripts, dev environments).
        # Use word-boundary regex to avoid matching substrings
        # (e.g., "git" inside "legit").
        import re as _re
        _DEV_TOOL_RE = _re.compile(
            r"\bclaude\b|\bnode\b|\bnpm\b|\bnpx\b|\byarn\b|\bpnpm\b"
            r"|\bcursor\b|\bpython\b|\bconda\b|\bdocker\b|\bgit\b|\bwsl\b",
            _re.IGNORECASE,
        )
        if _DEV_TOOL_RE.search(args_stripped):
            return None

    # Determine risk level
    if matched_patterns and is_suspicious_target:
        risk = RiskLevel.HIGH
        desc_text = f"Shortcut targets {target_name} with suspicious arguments"
    elif matched_patterns:
        risk = RiskLevel.HIGH
        desc_text = f"Shortcut contains suspicious command patterns"
    else:
        risk = RiskLevel.MEDIUM
        desc_text = f"Shortcut targets command interpreter: {target_name}"

    # Truncate for display safety
    display_target = target[:200] if target else "(empty)"
    display_args = arguments[:500] if arguments else "(none)"

    return Finding(
        module="Attack Vector Scanner",
        risk=risk,
        title=f"Suspicious shortcut: {basename}",
        description=desc_text,
        details={
            "path": filepath,
            "target": display_target,
            "arguments": display_args,
            "matched_patterns": ", ".join(matched_patterns) if matched_patterns else "suspicious target",
            "working_dir": lnk_data.get("working_dir", ""),
        },
        mitre_id="T1204.002",
        remediation=(
            "Inspect the shortcut target and arguments. "
            "Delete if unexpected or from an untrusted source."
        ),
    )


def _analyze_lnk(filepath: str) -> Optional[Finding]:
    """Analyze a .lnk file for suspicious targets and arguments.

    Parses the .lnk binary format and delegates to _analyze_lnk_data.

    Args:
        filepath: Path to the .lnk file.

    Returns:
        Finding if suspicious, None if benign or unparseable.
    """
    lnk_data = _parse_lnk(filepath)
    if not lnk_data:
        return None
    return _analyze_lnk_data(lnk_data, filepath)


def _analyze_disk_image(filepath: str, ext: str) -> Finding:
    """Flag disk image files (.iso, .img, .vhd, .vhdx) in user-writable dirs.

    Context-aware risk: Temp/AppData/Public -> HIGH, Downloads/Desktop -> MEDIUM.
    VHD/VHDX always HIGH (very uncommon for regular users).
    """
    basename = os.path.basename(filepath)
    ext_info = DANGEROUS_EXTENSIONS[ext]
    size_str = _safe_filesize(filepath)
    created = _safe_ctime(filepath)

    # Context-aware risk level
    if ext in (".vhd", ".vhdx"):
        # VHD/VHDX are almost never legitimate in user dirs
        risk = RiskLevel.HIGH
    elif _is_high_risk_location(filepath):
        # ISO/IMG in temp/appdata = delivery mechanism
        risk = RiskLevel.HIGH
    else:
        # ISO/IMG in Downloads/Desktop/Documents = could be legitimate
        risk = RiskLevel.MEDIUM

    # Large ISOs/IMGs (>200MB) are almost always legitimate OS images.
    # Weaponized MOTW-bypass ISOs are typically <50MB.
    fp_reason = None
    if ext in (".iso", ".img"):
        try:
            file_size = os.path.getsize(filepath)
            if file_size > 200 * 1024 * 1024:
                risk = RiskLevel.INFO
                fp_reason = f"Large file ({file_size // (1024*1024)}MB) — likely OS image"
        except OSError:
            pass

    # Known OS/security distribution ISOs — downgrade to INFO, not delete.
    # Bilinmeyen ISO → orijinal risk korunur (evil_payload.iso → MEDIUM/HIGH)
    if ext in (".iso", ".img") and not fp_reason:
        _KNOWN_OS_PATTERNS = (
            "kali-linux", "kali_linux", "ubuntu-", "debian-", "fedora-",
            "centos-", "tails-", "zorin-", "mint-", "arch-", "manjaro-",
            "parrot-", "en_windows_", "tr_windows_", "windows_server_",
            "vmware-", "esxi-", "proxmox-",
        )
        name_lower = basename.lower()
        if any(p in name_lower for p in _KNOWN_OS_PATTERNS):
            risk = RiskLevel.INFO
            fp_reason = "Known OS/security distribution"

    det = {
        "path": filepath,
        "extension": ext,
        "size": size_str,
        "created": created,
        "attack_technique": "MOTW bypass",
    }
    if fp_reason:
        det["fp_reason"] = fp_reason

    return Finding(
        module="Attack Vector Scanner",
        risk=risk,
        title=f"{ext_info['name']} in user directory: {basename}",
        description=(
            f"{ext_info['description']}. "
            f"Files inside disk images lack Zone.Identifier (MOTW bypass)."
        ),
        details=det,
        mitre_id=ext_info["mitre"],
        remediation=(
            "Verify the origin of this file. If unexpected, delete immediately. "
            "Check if the image was mounted and inspect any extracted contents."
        ),
    )


def _analyze_chm(filepath: str) -> Finding:
    """Flag .chm files in user-writable directories."""
    basename = os.path.basename(filepath)
    # CHM inside installed tools (Sysinternals, Program Files) are docs
    path_lower = filepath.lower()
    _SAFE_CHM_DIRS = (
        "\\program files\\", "\\program files (x86)\\",
        "\\sysinternals\\", "\\windows kits\\",
        # Sysinternals tools extracted to user directories
        "\\autoruns\\", "\\procmon\\", "\\procexp\\",
        "\\sysmon\\", "\\tcpview\\", "\\process monitor\\",
    )
    chm_risk = RiskLevel.INFO if any(d in path_lower for d in _SAFE_CHM_DIRS) else RiskLevel.HIGH
    return Finding(
        module="Attack Vector Scanner",
        risk=chm_risk,
        title=f"Compiled HTML Help file: {basename}",
        description=(
            "CHM files can execute embedded scripts and ActiveX controls. "
            "Commonly used for social engineering attacks."
        ),
        details={
            "path": filepath,
            "extension": ".chm",
            "size": _safe_filesize(filepath),
            "created": _safe_ctime(filepath),
        },
        mitre_id="T1218.001",
        remediation=(
            "Verify the origin of this CHM file. If unexpected, delete it. "
            "CHM files from the internet should be treated with extreme caution."
        ),
    )


def _analyze_xll(filepath: str) -> Finding:
    """Flag .xll files in user-writable directories."""
    basename = os.path.basename(filepath)
    return Finding(
        module="Attack Vector Scanner",
        risk=RiskLevel.HIGH,
        title=f"Excel add-in (XLL): {basename}",
        description=(
            "XLL files are native DLLs that execute code when loaded by Excel. "
            "Presence in user directories is highly suspicious."
        ),
        details={
            "path": filepath,
            "extension": ".xll",
            "size": _safe_filesize(filepath),
            "created": _safe_ctime(filepath),
        },
        mitre_id="T1137.006",
        remediation=(
            "Delete this file unless you explicitly installed it as an Excel add-in. "
            "XLL files are a common malware delivery mechanism."
        ),
    )


# ---------------------------------------------------------------------------
# Main Scan Entry Point
# ---------------------------------------------------------------------------

# OS-default .lnk directories — Windows-created shortcuts, not user-planted
_OS_DEFAULT_LNK_DIRS = (
    "\\start menu\\programs\\windows powershell\\",
    "\\start menu\\programs\\system tools\\",
    "\\start menu\\programs\\accessories\\",
    "\\start menu\\programs\\administrative tools\\",
    "\\default\\appdata\\",
    "\\default user\\appdata\\",
)


def scan() -> List[Finding]:
    """Scan user-writable directories for modern attack vector file types.

    Lightweight scanner that detects dangerous file extensions commonly
    used in initial access attacks.  Runs in ALL modes including --quick.

    Returns:
        List of Finding objects for detected dangerous files.
    """
    print_section("ATTACK VECTOR SCANNER - Dangerous File Extension Detection")
    findings: List[Finding] = []

    # Collect files
    print("  [i] Scanning user-writable directories for dangerous file types...")
    throttle = IOThrottle(ops_per_batch=300, sleep_seconds=0.005)
    scan_dirs = _resolve_scan_dirs()

    if not scan_dirs:
        print("  [i] No user directories found to scan.")
        return findings

    print(f"  [i] Directories to scan: {len(scan_dirs)}")

    dangerous_files = _collect_dangerous_files(scan_dirs, throttle)

    if not dangerous_files:
        print("  [+] No dangerous file types found in user directories.")
        return findings

    # Group by extension for reporting
    ext_counts: Dict[str, int] = {}
    for _, ext in dangerous_files:
        ext_counts[ext] = ext_counts.get(ext, 0) + 1

    count_str = ", ".join(
        f"{ext}: {count}" for ext, count in sorted(ext_counts.items())
    )
    print(f"  [i] Found {len(dangerous_files)} file(s): {count_str}")

    # Analyze each file
    for filepath, ext in dangerous_files:
        try:
            finding: Optional[Finding] = None

            if ext == ".lnk":
                # Skip OS-default shortcuts (Windows-created, not user-planted)
                path_lower = filepath.lower()
                if any(m in path_lower for m in _OS_DEFAULT_LNK_DIRS):
                    continue
                finding = _analyze_lnk(filepath)
            elif ext in (".iso", ".img", ".vhd", ".vhdx"):
                finding = _analyze_disk_image(filepath, ext)
            elif ext == ".chm":
                finding = _analyze_chm(filepath)
            elif ext == ".xll":
                finding = _analyze_xll(filepath)

            if finding:
                findings.append(finding)
                print_finding(finding)
        except Exception:
            continue

    print(f"  [i] Attack vector scan complete. {len(findings)} finding(s).")
    return findings
