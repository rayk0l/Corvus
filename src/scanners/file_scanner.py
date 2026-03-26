"""
file_scanner.py - Full disk file scanner with hash matching, YARA rules,
and string-based malware signature detection.

Scans ALL drives on the system:
  1. High-risk directories first (AppData, Temp, Downloads, ProgramData)
  2. Then remaining directories on all drives
  3. Hash matching against known malicious SHA256
  4. YARA rule scanning (primary detection engine)
  5. String-based signature scanning (fallback)

Uses I/O throttling and smart directory filtering to avoid system overload.
"""

import os
import json
import math
import struct
import string
import glob
import ctypes
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Set, Dict, Optional, Tuple

from scanner_core.utils import (
    Finding, RiskLevel, IOThrottle,
    load_ioc_file, calculate_sha256, get_resource_path,
    check_file_signature, is_os_native_path, is_known_dev_tool,
    print_section, print_finding,
)

# YARA import with graceful fallback
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False


# ---- Configuration ----

# File extensions to scan for hash + signatures
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".ps1", ".vbs", ".js", ".bat", ".cmd",
    ".scr", ".msi", ".hta", ".wsf", ".cpl",
}

# Additional extensions for signature-only scanning (not hashed)
SCRIPT_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".ashx", ".jsp",
    ".py", ".rb", ".pl",
}

ALL_TARGET_EXTENSIONS = EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS

# Max file size to hash (50 MB) and scan for strings (10 MB)
MAX_HASH_SIZE = 50 * 1024 * 1024
MAX_SIGNATURE_SCAN_SIZE = 10 * 1024 * 1024

# Thread pool size
MAX_WORKERS = 4

# Max depth for directory traversal
MAX_DEPTH = 10

# Directories to SKIP entirely (lowercase)
SKIP_DIRECTORIES = {
    "winsxs", "servicing", "installer", "assembly",
    "microsoft.net", "softwareDistribution",
    "node_modules", ".git", ".svn", ".hg",
    "__pycache__", ".tox", ".venv", "venv",
    "site-packages", "dist-packages",
    "$recycle.bin", "system volume information",
    "recovery", "boot",
}

# Directories to SKIP (full path prefixes, lowercase)
SKIP_PATH_PREFIXES = [
    "c:\\windows\\winsxs",
    "c:\\windows\\servicing",
    "c:\\windows\\installer",
    "c:\\windows\\assembly",
    "c:\\windows\\microsoft.net",
    "c:\\windows\\softwaredistribution",
]

# High-priority scan directories (scanned first)
HIGH_PRIORITY_PATTERNS = [
    os.path.join(os.environ.get("SystemDrive", "C:"), "\\Users\\*\\AppData\\Local\\Temp"),
    os.path.join(os.environ.get("SystemDrive", "C:"), "\\Users\\*\\AppData\\Roaming"),
    os.path.join(os.environ.get("SystemDrive", "C:"), "\\Users\\*\\Downloads"),
    os.path.join(os.environ.get("SystemDrive", "C:"), "\\Users\\*\\Desktop"),
    os.path.join(os.environ.get("SystemDrive", "C:"), "\\Users\\*\\Documents"),
    os.path.join(os.environ.get("SystemDrive", "C:"), "\\ProgramData"),
    os.path.join(os.environ.get("SystemDrive", "C:"), "\\Windows\\Temp"),
    os.path.join(os.environ.get("SystemDrive", "C:"), "\\Users\\Public"),
]


# ---- Malware Signature Engine ----

class SignatureEngine:
    """Loads and matches string-based malware signatures from JSON."""

    def __init__(self):
        self.signatures: List[Dict] = []
        self._load_signatures()

    def _load_signatures(self):
        path = get_resource_path(os.path.join("iocs", "malware_signatures.json"))
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.signatures = data.get("signatures", [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"  [!] Signature file error: {e}")

    def scan_file(self, filepath: str, content_bytes: bytes) -> List[Dict]:
        """Scan file content against all applicable signatures.
        Returns list of matched signature dicts."""
        matches = []
        ext = os.path.splitext(filepath)[1].lower()
        content_lower = content_bytes.lower()

        for sig in self.signatures:
            # Check if this signature applies to this file type
            file_types = sig.get("file_types", [])
            if file_types and ext not in file_types:
                continue

            strings = sig.get("strings", [])
            if not strings:
                continue

            # Count how many strings match
            matched_strings = []
            for s in strings:
                if s.lower().encode("utf-8", errors="ignore") in content_lower:
                    matched_strings.append(s)

            # Determine if it's a match based on the matching mode
            is_match = False

            if sig.get("match_all_required"):
                # ALL strings must match
                is_match = len(matched_strings) == len(strings)
            elif sig.get("match_count"):
                # At least N strings must match
                is_match = len(matched_strings) >= sig["match_count"]
            elif sig.get("match_any", False):
                # ANY single string is enough
                is_match = len(matched_strings) > 0
            else:
                # Default: any match
                is_match = len(matched_strings) > 0

            if is_match:
                matches.append({
                    "id": sig.get("id", "UNKNOWN"),
                    "name": sig.get("name", "Unknown Signature"),
                    "severity": sig.get("severity", "HIGH"),
                    "matched_strings": matched_strings,
                })

        return matches


# ---- Drive Discovery ----

def _get_all_drives() -> List[str]:
    """Get all available drive letters on the system."""
    drives = []
    try:
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for i in range(26):
            if bitmask & (1 << i):
                letter = chr(ord('A') + i)
                drive = f"{letter}:\\"
                # Only include fixed and removable drives (skip CD-ROM, network)
                drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive)
                if drive_type in (2, 3):  # REMOVABLE=2, FIXED=3
                    drives.append(drive)
    except Exception:
        drives = ["C:\\"]
    return drives


def _should_skip_dir(dir_path: str, dir_name: str) -> bool:
    """Check if a directory should be skipped."""
    name_lower = dir_name.lower()
    path_lower = dir_path.lower()

    if name_lower in SKIP_DIRECTORIES:
        return True

    for prefix in SKIP_PATH_PREFIXES:
        if path_lower.startswith(prefix):
            return True

    return False


# ---- File Collection ----

def _resolve_high_priority_dirs() -> List[str]:
    """Resolve glob patterns in high-priority directories."""
    resolved = []
    for pattern in HIGH_PRIORITY_PATTERNS:
        if "*" in pattern:
            resolved.extend(glob.glob(pattern))
        elif os.path.isdir(pattern):
            resolved.append(pattern)
    return list(set(resolved))


def _collect_files_from_dirs(
    directories: List[str],
    throttle: IOThrottle,
    max_depth: int = MAX_DEPTH,
    scanned_paths: set = None,
) -> List[str]:
    """Walk directories and collect target files."""
    files = []
    if scanned_paths is None:
        scanned_paths = set()

    for dir_path in directories:
        dir_path_norm = os.path.normpath(dir_path).lower()
        if dir_path_norm in scanned_paths:
            continue
        scanned_paths.add(dir_path_norm)

        try:
            for root, dirs, filenames in os.walk(dir_path):
                depth = root.replace(dir_path, "").count(os.sep)
                if depth > max_depth:
                    dirs.clear()
                    continue

                # Filter out directories to skip
                dirs[:] = [
                    d for d in dirs
                    if not _should_skip_dir(os.path.join(root, d), d)
                ]

                for fname in filenames:
                    ext = os.path.splitext(fname)[1].lower()
                    if ext in ALL_TARGET_EXTENSIONS:
                        full_path = os.path.join(root, fname)
                        try:
                            fsize = os.path.getsize(full_path)
                            if 0 < fsize <= MAX_HASH_SIZE:
                                files.append(full_path)
                        except OSError:
                            pass
                    throttle.tick()
        except (PermissionError, OSError):
            continue

    return files


def _collect_full_disk_files(
    throttle: IOThrottle,
    high_priority_dirs: List[str],
) -> Tuple[List[str], List[str]]:
    """Collect files from the entire disk, returning (high_priority, rest)."""
    scanned_paths = set()

    # Phase 1: High-priority directories
    hp_files = _collect_files_from_dirs(
        high_priority_dirs, throttle,
        max_depth=MAX_DEPTH, scanned_paths=scanned_paths,
    )

    # Phase 2: Remaining directories on all drives
    drives = _get_all_drives()
    remaining_dirs = []
    for drive in drives:
        try:
            for item in os.listdir(drive):
                full = os.path.join(drive, item)
                if os.path.isdir(full):
                    norm = os.path.normpath(full).lower()
                    if norm not in scanned_paths and not _should_skip_dir(full, item):
                        remaining_dirs.append(full)
        except (PermissionError, OSError):
            continue

    rest_files = _collect_files_from_dirs(
        remaining_dirs, throttle,
        max_depth=MAX_DEPTH, scanned_paths=scanned_paths,
    )

    return hp_files, rest_files


# ---- Scanning Logic ----

def _scan_single_file(
    filepath: str,
    bad_hashes: Set[str],
    sig_engine: SignatureEngine,
    yara_rules=None,
) -> List[Finding]:
    """Scan a single file: hash check + YARA + signature scan."""
    findings = []
    basename = os.path.basename(filepath)
    ext = os.path.splitext(filepath)[1].lower()
    filepath_lower = filepath.lower()

    # 1. Hash check (executables only — always runs, even for safe paths)
    if ext in EXECUTABLE_EXTENSIONS:
        file_hash = calculate_sha256(filepath)
        if file_hash and file_hash.lower() in bad_hashes:
            findings.append(Finding(
                module="File Scanner",
                risk=RiskLevel.CRITICAL,
                title=f"Malicious file detected: {basename}",
                description="File hash matches known malware signature.",
                details={
                    "path": filepath,
                    "sha256": file_hash,
                    "size": _safe_filesize(filepath),
                    "detection": "Hash Match",
                },
                mitre_id="T1204.002",
                remediation="Quarantine or delete the file immediately. Run a full antivirus scan on the system.",
            ))

    # Skip signature scan for files in known safe directories
    # (Hash check above still runs — we want to catch hash-matched malware everywhere)
    SAFE_SIGNATURE_DIRS = (
        "\\program files\\", "\\program files (x86)\\",
        "\\windows\\system32\\", "\\windows\\syswow64\\",
        "\\windows\\systemapps\\",
        "\\appdata\\local\\programs\\",
        "\\appdata\\local\\microsoft\\",
        "\\appdata\\local\\google\\",
        "\\appdata\\local\\brave",
        "\\appdata\\roaming\\zoom\\",
        "\\appdata\\roaming\\discord\\",
        "\\appdata\\roaming\\slack\\",
        "\\appdata\\roaming\\spotify\\",
        "\\microsoft office\\",
        "\\dotnet\\",
        "\\windowsapps\\",
        # IDE extensions — contain legitimate binaries that may trigger string sigs
        "\\.vscode\\extensions\\",
        "\\.vscode-insiders\\extensions\\",
        "\\.cursor\\extensions\\",
        "\\jetbrains\\",
    )
    if any(safe in filepath_lower for safe in SAFE_SIGNATURE_DIRS):
        return findings

    # 2. YARA rule scan (primary detection — only for files NOT in safe dirs)
    if yara_rules:
        try:
            matches = yara_rules.match(filepath, timeout=10)
            for match in matches:
                severity = match.meta.get("severity", "high").lower()
                risk = (
                    RiskLevel.CRITICAL if severity == "critical"
                    else RiskLevel.HIGH if severity == "high"
                    else RiskLevel.MEDIUM
                )
                matched_strings = []
                for offset, identifier, data in match.strings:
                    s = data.decode("utf-8", errors="replace")[:50]
                    if s not in matched_strings:
                        matched_strings.append(s)
                    if len(matched_strings) >= 5:
                        break

                findings.append(Finding(
                    module="File Scanner",
                    risk=risk,
                    title=f"YARA: {match.meta.get('description', match.rule)} — {basename}",
                    description=f"YARA rule '{match.rule}' matched.",
                    details={
                        "path": filepath,
                        "yara_rule": match.rule,
                        "description": match.meta.get("description", ""),
                        "matched_strings": ", ".join(matched_strings) if matched_strings else "(binary match)",
                        "size": _safe_filesize(filepath),
                        "detection": "YARA Rule",
                    },
                    mitre_id="T1204.002",
                    remediation="Quarantine the file and investigate its origin. Submit to VirusTotal for analysis.",
                ))
        except yara.TimeoutError:
            pass
        except yara.Error:
            pass
        except Exception:
            pass

    # 3. String-based signature scan (fallback — only for files NOT in safe dirs)
    try:
        fsize = os.path.getsize(filepath)
        if fsize > MAX_SIGNATURE_SCAN_SIZE:
            return findings  # Too large for string scanning

        with open(filepath, "rb") as f:
            content = f.read(MAX_SIGNATURE_SCAN_SIZE)

        matches = sig_engine.scan_file(filepath, content)
        for match in matches:
            severity = match.get("severity", "HIGH")
            risk = (
                RiskLevel.CRITICAL if severity == "CRITICAL"
                else RiskLevel.HIGH if severity == "HIGH"
                else RiskLevel.MEDIUM
            )
            findings.append(Finding(
                module="File Scanner",
                risk=risk,
                title=f"Malware signature: {match['name']} — {basename}",
                description=f"File contains strings matching {match['name']} ({match['id']}).",
                details={
                    "path": filepath,
                    "signature_id": match["id"],
                    "signature_name": match["name"],
                    "matched_strings": ", ".join(match["matched_strings"][:5]),
                    "size": _safe_filesize(filepath),
                    "detection": "Signature Match",
                },
                mitre_id="T1204.002",
                remediation="Delete or quarantine the file. Run a full system scan with updated antivirus definitions.",
            ))

    except (PermissionError, OSError, MemoryError):
        pass

    # 4. PE header + entropy analysis (executables only, Sprint 3.1)
    if ext in PE_EXTENSIONS:
        try:
            sig_result = check_file_signature(filepath)
            is_native = is_os_native_path(filepath)
            pe_findings = _analyze_pe_headers(
                filepath, sig_result=sig_result, is_native=is_native,
            )
            findings.extend(pe_findings)
        except Exception:
            pass

    return findings


# ---- PE Header + Entropy Analysis (Sprint 3.1) ----

# PE extensions eligible for header analysis
PE_EXTENSIONS = {".exe", ".dll", ".scr", ".cpl"}

# Known packer / protector section names (lowercase, stripped of null bytes)
PACKER_SECTION_NAMES = {
    "upx0", "upx1", "upx2", "upx!",
    ".enigma", ".enigma1", ".enigma2",
    ".vmp0", ".vmp1", ".vmp2", ".vmprotect",
    ".themida",
    ".aspack", ".adata",
    ".petite",
    ".nsp0", ".nsp1", ".nsp2",
    ".packed",
    ".mpress1", ".mpress2",
    ".perplex",
}

# PE section characteristic flags
_IMAGE_SCN_MEM_EXECUTE = 0x20000000
_IMAGE_SCN_MEM_WRITE = 0x80000000

# Max bytes to read per section for entropy calculation
_MAX_ENTROPY_READ = 256 * 1024  # 256 KB


def _calculate_shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte sequence.

    Returns a value between 0.0 (all identical bytes) and 8.0 (uniformly
    random bytes). Values above 7.0 strongly suggest compressed, encrypted,
    or packed content.
    """
    if not data:
        return 0.0
    length = len(data)
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    for count in freq:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy


_PACKER_TOOL_NAMES = {"upx.exe", "upx", "mpress.exe", "petite.exe"}


def _is_packer_tool_itself(filepath: str, sig_result: Dict) -> bool:
    """Detect if binary is a packer TOOL (not packed malware).

    Requires ALL of:
      1. Filename matches known packer tool names
      2. File is signed OR in a legitimate path (Downloads, Program Files)
      3. File contains packer tool signatures (help text, version strings)

    Multi-condition: attacker can rename binary, but can't easily fake
    embedded tool strings + signed status + filename all together.
    """
    filename = os.path.basename(filepath).lower()
    if filename not in _PACKER_TOOL_NAMES:
        return False

    # Condition 2: signed OR legitimate path
    legitimate_paths = (
        "\\program files", "\\tools\\",
        "\\downloads\\", "\\desktop\\",
    )
    in_legit_path = any(
        p in filepath.lower() for p in legitimate_paths
    )
    if not sig_result.get("signed") and not in_legit_path:
        return False  # Suspicious location + unsigned = NOT trusted

    # Condition 3: contains packer tool strings
    try:
        with open(filepath, "rb") as f:
            header = f.read(8192)
        tool_sigs = [b"Ultimate Packer for eXecutables", b"UPX", b"--best"]
        if any(s in header for s in tool_sigs):
            return True
    except (OSError, PermissionError):
        pass

    return False


def _evaluate_pe_finding(
    sig_result: Dict,
    is_native: bool,
    original_risk: RiskLevel,
) -> Tuple[RiskLevel, Optional[str]]:
    """Evaluate PE analysis finding considering signature status.

    Returns (adjusted_risk, fp_reason or None).

    Three-tier logic:
    - Signed + trusted vendor → INFO (still reported, informational)
    - Signed + unknown vendor → MEDIUM (cautious downgrade)
    - Unsigned → original risk (no adjustment)

    Signed ≠ safe (SolarWinds). Finding is NEVER deleted.
    """
    signer = sig_result.get("signer", "Unknown")

    if sig_result.get("trusted"):
        fp_reason = f"Signed by trusted vendor: {signer}"
        return RiskLevel.INFO, fp_reason

    if sig_result.get("signed"):
        fp_reason = f"Signed (not in trusted list): {signer}"
        if original_risk == RiskLevel.HIGH:
            return RiskLevel.MEDIUM, fp_reason
        return original_risk, None  # MEDIUM stays MEDIUM

    if is_native:
        fp_reason = "OS-native path (unsigned)"
        return RiskLevel.INFO, fp_reason

    # Unsigned — full risk, no downgrade
    return original_risk, None


def _analyze_pe_headers(
    filepath: str,
    sig_result: Optional[Dict] = None,
    is_native: bool = False,
) -> List[Finding]:
    """Analyze PE section headers for packing/encryption indicators.

    Performs three checks:
      1. Known packer section names (UPX, Themida, VMProtect, etc.)
      2. High entropy sections (>7.0 — packed/encrypted)
      3. RWX sections (writable + executable — self-modifying code)

    Returns findings for suspicious characteristics. Gracefully returns
    empty list for non-PE files, truncated files, or on any I/O error.

    MITRE: T1027.002 (Obfuscated Files or Information: Software Packing)
    """
    if sig_result is None:
        sig_result = {}
    findings = []
    basename = os.path.basename(filepath)

    try:
        with open(filepath, "rb") as f:
            # ---- DOS Header ----
            dos_header = f.read(64)
            if len(dos_header) < 64 or dos_header[:2] != b"MZ":
                return findings

            e_lfanew = struct.unpack_from("<I", dos_header, 0x3C)[0]
            if e_lfanew > 0x100000:  # PE header offset > 1 MB — bogus
                return findings

            # ---- PE Signature ----
            f.seek(e_lfanew)
            pe_sig = f.read(4)
            if pe_sig != b"PE\x00\x00":
                return findings

            # ---- COFF Header (20 bytes) ----
            coff = f.read(20)
            if len(coff) < 20:
                return findings
            num_sections = struct.unpack_from("<H", coff, 2)[0]
            optional_header_size = struct.unpack_from("<H", coff, 16)[0]

            if num_sections == 0 or num_sections > 96:
                return findings

            # ---- Skip Optional Header → Section Table ----
            f.seek(e_lfanew + 4 + 20 + optional_header_size)

            # ---- Parse Section Table (40 bytes per entry) ----
            sections = []
            for _ in range(num_sections):
                sec_data = f.read(40)
                if len(sec_data) < 40:
                    break
                name_raw = sec_data[:8].rstrip(b"\x00").decode(
                    "ascii", errors="replace"
                ).lower().strip()
                raw_size = struct.unpack_from("<I", sec_data, 16)[0]
                raw_ptr = struct.unpack_from("<I", sec_data, 20)[0]
                characteristics = struct.unpack_from("<I", sec_data, 36)[0]
                sections.append({
                    "name": name_raw,
                    "raw_size": raw_size,
                    "raw_ptr": raw_ptr,
                    "characteristics": characteristics,
                })

            # ---- Analysis ----
            packer_sections = []
            high_entropy_sections = []
            rwx_sections = []

            for sec in sections:
                # Check 1: Known packer section names
                if sec["name"] in PACKER_SECTION_NAMES:
                    packer_sections.append(sec["name"])

                # Check 2: RWX (writable + executable)
                # Exclude .textbss — compiler-generated uninitialized BSS segment,
                # commonly has RWX flags but is not a real threat.
                chars = sec["characteristics"]
                if (chars & _IMAGE_SCN_MEM_EXECUTE) and (chars & _IMAGE_SCN_MEM_WRITE):
                    if sec["name"] != ".textbss":
                        rwx_sections.append(sec["name"])

                # Check 3: Shannon entropy (only for sections with raw data)
                if sec["raw_size"] > 0 and sec["raw_ptr"] > 0:
                    try:
                        f.seek(sec["raw_ptr"])
                        chunk = f.read(min(sec["raw_size"], _MAX_ENTROPY_READ))
                        if chunk:
                            entropy = _calculate_shannon_entropy(chunk)
                            if entropy > 7.0:
                                high_entropy_sections.append(
                                    (sec["name"], round(entropy, 2))
                                )
                    except OSError:
                        pass

            # ---- Generate Findings ----
            if packer_sections:
                # Check if this is a packer tool itself (e.g., upx.exe)
                if _is_packer_tool_itself(filepath, sig_result):
                    findings.append(Finding(
                        module="File Scanner",
                        risk=RiskLevel.INFO,
                        title=f"Packer tool detected: {basename}",
                        description=(
                            "This is a packer utility, not packed malware."
                        ),
                        details={
                            "path": filepath,
                            "packer_sections": packer_sections,
                            "size": _safe_filesize(filepath),
                            "detection": "PE Header Analysis",
                            "fp_reason": "Binary is a packer tool itself (UPX/MPRESS)",
                            "original_risk": RiskLevel.HIGH.value,
                        },
                        mitre_id="T1027.002",
                        remediation="No action needed — this is a packing utility.",
                    ))
                else:
                    adj_risk, fp_reason = _evaluate_pe_finding(
                        sig_result, is_native, RiskLevel.HIGH,
                    )
                    det = {
                        "path": filepath,
                        "packer_sections": packer_sections,
                        "size": _safe_filesize(filepath),
                        "detection": "PE Header Analysis",
                    }
                    if fp_reason:
                        det["fp_reason"] = fp_reason
                        det["original_risk"] = RiskLevel.HIGH.value
                    findings.append(Finding(
                        module="File Scanner",
                        risk=adj_risk,
                        title=f"Packed executable detected: {basename}",
                        description=(
                            f"PE file contains known packer section(s): "
                            f"{', '.join(packer_sections)}. Packed executables are "
                            "commonly used to evade antivirus detection."
                        ),
                        details=det,
                        mitre_id="T1027.002",
                        remediation=(
                            "Investigate the origin of this packed executable. "
                            "Submit to VirusTotal or a sandbox for dynamic analysis."
                        ),
                    ))

            if high_entropy_sections:
                # .rsrc sections naturally have high entropy (compressed icons,
                # images, manifests). If ONLY .rsrc is high-entropy with no
                # other suspicious sections, suppress entirely — pure noise.
                _RESOURCE_ONLY = {".rsrc", ".qtmimed"}
                entropy_names = {n for n, _ in high_entropy_sections}
                if entropy_names.issubset(_RESOURCE_ONLY) and not packer_sections and not rwx_sections:
                    pass  # suppress — resource-only entropy is not suspicious
                else:
                    names_str = ", ".join(
                        f"{n} ({e})" for n, e in high_entropy_sections
                    )
                    adj_risk, fp_reason = _evaluate_pe_finding(
                        sig_result, is_native, RiskLevel.MEDIUM,
                    )
                    det = {
                        "path": filepath,
                        "high_entropy_sections": {
                            n: e for n, e in high_entropy_sections
                        },
                        "size": _safe_filesize(filepath),
                        "detection": "Entropy Analysis",
                    }
                    if fp_reason:
                        det["fp_reason"] = fp_reason
                        det["original_risk"] = RiskLevel.MEDIUM.value
                    findings.append(Finding(
                        module="File Scanner",
                        risk=adj_risk,
                        title=f"High-entropy PE sections: {basename}",
                        description=(
                            f"PE sections with entropy >7.0 (packed/encrypted): "
                            f"{names_str}. This may indicate the executable is "
                            "packed or contains encrypted payloads."
                        ),
                        details=det,
                        mitre_id="T1027.002",
                        remediation=(
                            "Analyze the executable with a disassembler or sandbox. "
                            "High entropy in code sections suggests packing or encryption."
                        ),
                    ))

            if rwx_sections and not packer_sections:
                # Only flag RWX if no packer already found (avoid double-flagging)
                adj_risk, fp_reason = _evaluate_pe_finding(
                    sig_result, is_native, RiskLevel.MEDIUM,
                )
                det = {
                    "path": filepath,
                    "rwx_sections": rwx_sections,
                    "detection": "PE Characteristic Analysis",
                }
                if fp_reason:
                    det["fp_reason"] = fp_reason
                    det["original_risk"] = RiskLevel.MEDIUM.value
                findings.append(Finding(
                    module="File Scanner",
                    risk=adj_risk,
                    title=f"RWX PE sections: {basename}",
                    description=(
                        f"PE has sections with Read+Write+Execute permissions: "
                        f"{', '.join(rwx_sections)}. This is unusual and may "
                        "indicate self-modifying code or runtime unpacking."
                    ),
                    details=det,
                    mitre_id="T1027.002",
                    remediation=(
                        "Investigate why this executable has writable+executable "
                        "sections. Legitimate software rarely needs RWX permissions."
                    ),
                ))

    except (PermissionError, OSError, struct.error, ValueError):
        pass

    return findings


def _safe_filesize(path: str) -> str:
    try:
        size = os.path.getsize(path)
        if size < 1024:
            return f"{size} B"
        elif size < 1024 * 1024:
            return f"{size / 1024:.1f} KB"
        else:
            return f"{size / (1024 * 1024):.1f} MB"
    except OSError:
        return "Unknown"


# ---- Main Scan Entry Point ----

def _load_yara_rules(rules_dir: str = None):
    """Load and compile YARA rules from custom and community directories.

    Strategy:
      1. Walk all ``.yar`` files recursively (custom + community)
      2. Skip disabled rules listed in ``disabled_rules.txt``
      3. Skip ``_broken/`` directories
      4. **Phase A** — compile all at once (fast path)
      5. **Phase B** (fallback) — per-file compile, skip broken ones

    Namespaces prevent rule-name collisions between custom and community
    rules: root-level files get ``custom__<name>``, subdirectory files get
    ``<subdir>__<name>`` (e.g. ``community__neo23x0__apt_apt10``).
    """
    if not YARA_AVAILABLE:
        return None

    if rules_dir is None:
        rules_dir = get_resource_path("yara_rules")
    if not os.path.isdir(rules_dir):
        return None

    # ---- Load disabled rules list ----
    disabled: set = set()
    disabled_path = os.path.join(rules_dir, "disabled_rules.txt")
    if os.path.isfile(disabled_path):
        try:
            with open(disabled_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        disabled.add(line)
        except OSError:
            pass

    # ---- Collect .yar files with unique namespaces ----
    rule_files: dict = {}  # namespace -> filepath
    custom_count = 0
    community_count = 0
    disabled_count = 0

    for root, dirs, files in os.walk(rules_dir):
        # Skip _broken/ directories entirely
        dirs[:] = [d for d in dirs if d != "_broken"]

        for filename in sorted(files):
            if not filename.endswith((".yar", ".yara")):
                continue

            # Check disabled list
            if filename in disabled:
                disabled_count += 1
                continue

            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(root, rules_dir)

            # Generate namespace to prevent rule-name collisions
            base_name = os.path.splitext(filename)[0]
            if rel_path in (".", ""):
                # Custom rules (root level)
                namespace = f"custom__{base_name}"
                custom_count += 1
            else:
                # Community rules (subdirectories)
                prefix = rel_path.replace(os.sep, "__").replace("/", "__")
                namespace = f"{prefix}__{base_name}"
                community_count += 1

            rule_files[namespace] = filepath

    if not rule_files:
        print("  [i] YARA: no rules found")
        return None

    # ---- Phase A: batch compile (fast path) ----
    try:
        rules = yara.compile(filepaths=rule_files)
        parts = []
        if custom_count:
            parts.append(f"{custom_count} custom")
        if community_count:
            parts.append(f"{community_count} community")
        msg = f"  [i] YARA: {' + '.join(parts)} rules loaded"
        if disabled_count:
            msg += f" ({disabled_count} disabled)"
        print(msg)
        return rules
    except yara.SyntaxError:
        pass  # Fall through to Phase B

    # ---- Phase B: per-file compile (resilient fallback) ----
    print("  [i] YARA: batch compile failed, trying per-file mode...")
    valid_files: dict = {}
    broken_count = 0

    for namespace, filepath in rule_files.items():
        try:
            yara.compile(filepath=filepath)
            valid_files[namespace] = filepath
        except (yara.SyntaxError, yara.Error) as e:
            fname = os.path.basename(filepath)
            print(f"  [!] YARA skip: {fname}: {e}")
            broken_count += 1

    if not valid_files:
        print("  [!] YARA: no valid rules after per-file check")
        return None

    try:
        rules = yara.compile(filepaths=valid_files)
        total = len(valid_files)
        msg = f"  [i] YARA: {total} rules loaded ({broken_count} broken"
        if disabled_count:
            msg += f", {disabled_count} disabled"
        msg += ")"
        print(msg)
        return rules
    except Exception as e:
        print(f"  [!] YARA compile error: {e}")
        return None


def scan() -> List[Finding]:
    """Run the full disk file scanner and return findings."""
    print_section("FILE SCANNER - Full Disk Hash + YARA + Signature Scan")
    findings = []

    # Load IOCs
    bad_hashes = load_ioc_file("bad_hashes.txt")
    if not bad_hashes:
        print("  [!] No hashes loaded from IOC file.")
    else:
        print(f"  [i] Loaded {len(bad_hashes)} known malicious hashes")

    # Load YARA rules
    yara_rules = _load_yara_rules()
    if yara_rules:
        print(f"  [i] YARA engine loaded ({YARA_AVAILABLE})")
    else:
        print("  [!] YARA not available — using string signatures only")

    sig_engine = SignatureEngine()
    sig_count = len(sig_engine.signatures)
    print(f"  [i] Loaded {sig_count} string-based signatures")

    # Discover drives
    drives = _get_all_drives()
    print(f"  [i] Drives found: {', '.join(drives)}")

    # Collect files
    print("  [i] Collecting files for scanning...")
    throttle = IOThrottle(ops_per_batch=200, sleep_seconds=0.01)
    high_priority_dirs = _resolve_high_priority_dirs()

    hp_files, rest_files = _collect_full_disk_files(throttle, high_priority_dirs)
    # Deduplicate: Phase 2 walk may revisit subdirs already scanned in Phase 1
    _seen_paths: set = set()
    unique_files: List[str] = []
    for _fp in hp_files + rest_files:
        _norm = os.path.normpath(_fp).lower()
        if _norm not in _seen_paths:
            _seen_paths.add(_norm)
            unique_files.append(_fp)
    all_files = unique_files
    total = len(all_files)
    print(f"  [i] Phase 1 (high-risk dirs): {len(hp_files)} files")
    print(f"  [i] Phase 2 (full disk):      {len(rest_files)} files")
    print(f"  [i] Total files to scan:      {total}")

    if not all_files:
        print("  [i] No target files found.")
        return findings

    # Scan files — same-hash dedup: identical binaries in multiple
    # locations are collapsed into one finding with duplicate_paths.
    # Safe because same SHA256 = same bytes = same threat.
    scanned = 0
    _seen_hashes: Dict[str, Finding] = {}  # sha256 -> first Finding
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        batch_size = 50
        for i in range(0, total, batch_size):
            batch = all_files[i:i + batch_size]
            futures = {
                executor.submit(_scan_single_file, fp, bad_hashes, sig_engine, yara_rules): fp
                for fp in batch
            }

            for future in as_completed(futures):
                try:
                    file_findings = future.result()
                    for f in file_findings:
                        sha = f.details.get("sha256")
                        if sha and sha in _seen_hashes:
                            first = _seen_hashes[sha]
                            first.details.setdefault(
                                "duplicate_paths", []
                            ).append(f.details.get("path", ""))
                            continue  # Skip duplicate binary
                        if sha:
                            _seen_hashes[sha] = f
                        findings.append(f)
                        print_finding(f)
                except Exception:
                    pass
                scanned += 1

                if scanned % 500 == 0:
                    print(f"  [i] Progress: {scanned}/{total} files scanned...")

    print(f"  [i] File scan complete. {scanned} files scanned, {len(findings)} findings.")
    return findings
