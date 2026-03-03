"""
utils.py - Core utilities for the security scanner.
Provides IOC loading, hashing, signature checking, OS info,
trusted vendor recognition, I/O throttling, and console helpers.
"""

import os
import sys
import hashlib
import ctypes
import ctypes.wintypes
import time
import subprocess
import platform
import re
from typing import Optional, Set, Tuple, List
from functools import lru_cache
from collections import OrderedDict

# Re-export models so existing `from scanner_core.utils import Finding, RiskLevel`
# (and future `from utils import ...` shims) continue to work.
from scanner_core.models import Finding, RiskLevel, calculate_risk_score


# ---------------------------------------------------------------------------
# Resource / IOC Path Resolution
# ---------------------------------------------------------------------------
def get_resource_path(relative_path: str) -> str:
    """Resolve path for Nuitka onefile, PyInstaller bundle, and dev mode."""
    # 1. Nuitka onefile — data extracted beside the binary
    nuitka_dir = globals().get("__nuitka_binary_dir")
    if nuitka_dir:
        base = nuitka_dir
    # 2. PyInstaller (legacy)
    elif getattr(sys, "_MEIPASS", None):
        base = sys._MEIPASS
    # 3. Dev mode — src/scanner_core/ -> src/ -> project root
    else:
        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, relative_path)


def load_ioc_file(filename: str) -> Set[str]:
    """Load an IOC file (one entry per line). Lines starting with # are comments."""
    path = get_resource_path(os.path.join("iocs", filename))
    entries: Set[str] = set()
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    entries.add(line.lower())
    except FileNotFoundError:
        print(f"  [!] IOC file not found: {path}")
    return entries


# ---------------------------------------------------------------------------
# OS Information (Cached)
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def get_os_info() -> dict:
    """Get detailed OS information for context-aware scanning."""
    info = {
        "platform": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "build": 0,
        "is_win11": False,
        "is_win10_1709_plus": False,
        "is_server": False,
    }

    try:
        ver_str = platform.version()
        # e.g., "10.0.26200" or "10.0.19041"
        parts = ver_str.split(".")
        if len(parts) >= 3:
            info["build"] = int(parts[2])

        # Windows 11 = build >= 22000
        if info["build"] >= 22000:
            info["is_win11"] = True
            info["is_win10_1709_plus"] = True
        # Windows 10 1709 = build >= 16299
        elif info["build"] >= 16299:
            info["is_win10_1709_plus"] = True

        # Check if Windows Server
        edition = platform.win32_edition() if hasattr(platform, "win32_edition") else ""
        if "server" in str(edition).lower():
            info["is_server"] = True
    except Exception:
        pass

    return info


# ---------------------------------------------------------------------------
# SHA256 Hashing (Low Memory - 8KB Chunks)
# ---------------------------------------------------------------------------
# SHA256 of empty (0-byte) file — always skip
EMPTY_FILE_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def calculate_sha256(filepath: str) -> Optional[str]:
    """Calculate SHA256 of a file using small chunks to avoid memory spikes.
    Returns None for 0-byte files or on error."""
    try:
        # Skip 0-byte files
        if os.path.getsize(filepath) == 0:
            return None

        h = hashlib.sha256()
        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        digest = h.hexdigest()

        # Double-check: skip empty file hash
        if digest == EMPTY_FILE_HASH:
            return None

        return digest
    except (PermissionError, OSError):
        return None


# ---------------------------------------------------------------------------
# Digital Signature Verification — ctypes WinVerifyTrust + PowerShell fallback
# ---------------------------------------------------------------------------

# ---- WinVerifyTrust / Catalog Signing API — ctypes definitions ----

class _GUID(ctypes.Structure):
    """Windows GUID structure (16 bytes)."""
    _fields_ = [
        ("Data1", ctypes.wintypes.DWORD),
        ("Data2", ctypes.wintypes.WORD),
        ("Data3", ctypes.wintypes.WORD),
        ("Data4", ctypes.c_ubyte * 8),
    ]


# WINTRUST_ACTION_GENERIC_VERIFY_V2 = {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
_WINTRUST_ACTION_GENERIC_VERIFY_V2 = _GUID(
    0x00AAC56B, 0xCD44, 0x11D0,
    (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE)
)

# WinVerifyTrust constants
_WTD_UI_NONE = 2
_WTD_CHOICE_FILE = 1
_WTD_CHOICE_CATALOG = 2
_WTD_REVOKE_NONE = 0
_WTD_STATEACTION_VERIFY = 1
_WTD_STATEACTION_CLOSE = 2
_WTD_SAFER_FLAG = 0x0100
_WTD_CACHE_ONLY_URL_RETRIEVAL = 0x1000    # offline — skip CRL/OCSP

# CertGetNameString
_CERT_NAME_SIMPLE_DISPLAY_TYPE = 4

# CreateFileW
_GENERIC_READ = 0x80000000
_FILE_SHARE_READ = 0x00000001
_OPEN_EXISTING = 3
_FILE_ATTRIBUTE_NORMAL = 0x00000080
_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# WinVerifyTrust return codes
_TRUST_E_NOSIGNATURE = 0x800B0100


class _WINTRUST_FILE_INFO(ctypes.Structure):
    """WINTRUST_FILE_INFO — file to verify (embedded Authenticode)."""
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pcwszFilePath", ctypes.c_wchar_p),
        ("hFile", ctypes.wintypes.HANDLE),
        ("pgKnownSubject", ctypes.POINTER(_GUID)),
    ]


class _WINTRUST_CATALOG_INFO(ctypes.Structure):
    """WINTRUST_CATALOG_INFO — catalog-signed file verification."""
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("dwCatalogVersion", ctypes.wintypes.DWORD),
        ("pcwszCatalogFilePath", ctypes.c_wchar_p),
        ("pcwszMemberTag", ctypes.c_wchar_p),
        ("pcwszMemberFilePath", ctypes.c_wchar_p),
        ("hMemberFile", ctypes.wintypes.HANDLE),
        ("pbCalculatedFileHash", ctypes.POINTER(ctypes.c_ubyte)),
        ("cbCalculatedFileHash", ctypes.wintypes.DWORD),
        ("pcCatalogContext", ctypes.c_void_p),
        ("hCatAdmin", ctypes.c_void_p),
    ]


class _WINTRUST_DATA(ctypes.Structure):
    """WINTRUST_DATA — main WinVerifyTrust input structure."""
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("pPolicyCallbackData", ctypes.c_void_p),
        ("pSIPClientData", ctypes.c_void_p),
        ("dwUIChoice", ctypes.wintypes.DWORD),
        ("fdwRevocationChecks", ctypes.wintypes.DWORD),
        ("dwUnionChoice", ctypes.wintypes.DWORD),
        ("pUnionData", ctypes.c_void_p),
        ("dwStateAction", ctypes.wintypes.DWORD),
        ("hWVTStateData", ctypes.wintypes.HANDLE),
        ("pwszURLReference", ctypes.c_wchar_p),
        ("dwProvFlags", ctypes.wintypes.DWORD),
        ("dwUIContext", ctypes.wintypes.DWORD),
        ("pSignatureSettings", ctypes.c_void_p),
    ]


class _CATALOG_INFO(ctypes.Structure):
    """CATALOG_INFO — output from CryptCATCatalogInfoFromContext."""
    _fields_ = [
        ("cbStruct", ctypes.wintypes.DWORD),
        ("wszCatalogFile", ctypes.c_wchar * 260),
    ]


# ---- API availability probe (import time) ----
_WINTRUST_AVAILABLE = False
try:
    _wintrust_dll = ctypes.windll.wintrust
    _crypt32_dll = ctypes.windll.crypt32
    _kernel32_dll = ctypes.windll.kernel32

    # Probe all required function pointers
    _wintrust_dll.WinVerifyTrust
    _wintrust_dll.WTHelperProvDataFromStateData
    _wintrust_dll.WTHelperGetProvSignerFromChain
    _wintrust_dll.CryptCATAdminAcquireContext2
    _wintrust_dll.CryptCATAdminCalcHashFromFileHandle2
    _wintrust_dll.CryptCATAdminEnumCatalogFromHash
    _wintrust_dll.CryptCATCatalogInfoFromContext
    _wintrust_dll.CryptCATAdminReleaseCatalogContext
    _wintrust_dll.CryptCATAdminReleaseContext
    _crypt32_dll.CertGetNameStringW

    # ---- argtypes / restype for type safety ----
    _wintrust_dll.WinVerifyTrust.argtypes = [
        ctypes.wintypes.HANDLE, ctypes.POINTER(_GUID), ctypes.c_void_p,
    ]
    _wintrust_dll.WinVerifyTrust.restype = ctypes.wintypes.LONG

    _wintrust_dll.WTHelperProvDataFromStateData.argtypes = [ctypes.wintypes.HANDLE]
    _wintrust_dll.WTHelperProvDataFromStateData.restype = ctypes.c_void_p

    _wintrust_dll.WTHelperGetProvSignerFromChain.argtypes = [
        ctypes.c_void_p, ctypes.wintypes.DWORD,
        ctypes.wintypes.BOOL, ctypes.wintypes.DWORD,
    ]
    _wintrust_dll.WTHelperGetProvSignerFromChain.restype = ctypes.c_void_p

    _wintrust_dll.CryptCATAdminAcquireContext2.argtypes = [
        ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
        ctypes.c_wchar_p, ctypes.c_void_p, ctypes.wintypes.DWORD,
    ]
    _wintrust_dll.CryptCATAdminAcquireContext2.restype = ctypes.wintypes.BOOL

    _wintrust_dll.CryptCATAdminCalcHashFromFileHandle2.argtypes = [
        ctypes.c_void_p, ctypes.wintypes.HANDLE,
        ctypes.POINTER(ctypes.wintypes.DWORD),
        ctypes.POINTER(ctypes.c_ubyte), ctypes.wintypes.DWORD,
    ]
    _wintrust_dll.CryptCATAdminCalcHashFromFileHandle2.restype = ctypes.wintypes.BOOL

    _wintrust_dll.CryptCATAdminEnumCatalogFromHash.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.c_ubyte),
        ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    _wintrust_dll.CryptCATAdminEnumCatalogFromHash.restype = ctypes.c_void_p

    _wintrust_dll.CryptCATCatalogInfoFromContext.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(_CATALOG_INFO), ctypes.wintypes.DWORD,
    ]
    _wintrust_dll.CryptCATCatalogInfoFromContext.restype = ctypes.wintypes.BOOL

    _wintrust_dll.CryptCATAdminReleaseCatalogContext.argtypes = [
        ctypes.c_void_p, ctypes.c_void_p, ctypes.wintypes.DWORD,
    ]
    _wintrust_dll.CryptCATAdminReleaseCatalogContext.restype = ctypes.wintypes.BOOL

    _wintrust_dll.CryptCATAdminReleaseContext.argtypes = [
        ctypes.c_void_p, ctypes.wintypes.DWORD,
    ]
    _wintrust_dll.CryptCATAdminReleaseContext.restype = ctypes.wintypes.BOOL

    _crypt32_dll.CertGetNameStringW.argtypes = [
        ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
        ctypes.c_void_p, ctypes.c_wchar_p, ctypes.wintypes.DWORD,
    ]
    _crypt32_dll.CertGetNameStringW.restype = ctypes.wintypes.DWORD

    _kernel32_dll.CreateFileW.argtypes = [
        ctypes.c_wchar_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
        ctypes.c_void_p, ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
        ctypes.wintypes.HANDLE,
    ]
    _kernel32_dll.CreateFileW.restype = ctypes.wintypes.HANDLE

    _WINTRUST_AVAILABLE = True
except (OSError, AttributeError):
    _WINTRUST_AVAILABLE = False


# ---- LRU Signature Cache (bounded, max 2000 entries) ----

class _LRUSignatureCache:
    """OrderedDict-based LRU cache for signature check results.

    Max 2000 entries to bound memory during heavy DLL/file scans.
    """

    def __init__(self, maxsize: int = 2000):
        self._cache: OrderedDict = OrderedDict()
        self._maxsize = maxsize

    def get(self, key: str) -> Optional[dict]:
        """Get cached result, moving to end (most recently used)."""
        if key in self._cache:
            self._cache.move_to_end(key)
            return self._cache[key]
        return None

    def put(self, key: str, value: dict) -> None:
        """Store result, evicting oldest entry if at capacity."""
        if key in self._cache:
            self._cache.move_to_end(key)
        elif len(self._cache) >= self._maxsize:
            self._cache.popitem(last=False)
        self._cache[key] = value


_signature_cache = _LRUSignatureCache(maxsize=2000)


# ---- Private helpers: ctypes WinVerifyTrust ----

def _wintrust_verify_embedded(filepath: str) -> Tuple[int, ctypes.c_void_p]:
    """Verify embedded Authenticode signature using WinVerifyTrust.

    Args:
        filepath: Absolute path to the file to verify.

    Returns:
        Tuple of (hresult, wintrust_data_pointer).
        hresult 0 = valid signature. Caller MUST call _close_wintrust_state()
        on the returned pointer after extracting signer info.
    """
    file_info = _WINTRUST_FILE_INFO()
    file_info.cbStruct = ctypes.sizeof(_WINTRUST_FILE_INFO)
    file_info.pcwszFilePath = filepath
    file_info.hFile = None
    file_info.pgKnownSubject = None

    wd = _WINTRUST_DATA()
    wd.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
    wd.dwUIChoice = _WTD_UI_NONE
    wd.fdwRevocationChecks = _WTD_REVOKE_NONE
    wd.dwUnionChoice = _WTD_CHOICE_FILE
    wd.pUnionData = ctypes.cast(ctypes.pointer(file_info), ctypes.c_void_p)
    wd.dwStateAction = _WTD_STATEACTION_VERIFY
    wd.hWVTStateData = None
    wd.dwProvFlags = _WTD_SAFER_FLAG | _WTD_CACHE_ONLY_URL_RETRIEVAL

    hr = _wintrust_dll.WinVerifyTrust(
        ctypes.c_void_p(_INVALID_HANDLE_VALUE),
        ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
        ctypes.byref(wd),
    )
    return (hr, wd)


def _catalog_verify(filepath: str) -> Tuple[int, Optional[_WINTRUST_DATA]]:
    """Verify catalog-based signature (Windows built-ins like svchost, notepad).

    Uses CryptCATAdmin APIs to find the catalog entry for a file,
    then verifies the catalog with WinVerifyTrust.

    Args:
        filepath: Absolute path to the file to verify.

    Returns:
        Tuple of (hresult, wintrust_data). Caller MUST call
        _close_wintrust_state() on success.
    """
    h_cat_admin = ctypes.c_void_p(0)
    h_cat_info = ctypes.c_void_p(0)
    h_file = ctypes.wintypes.HANDLE(0)

    try:
        # 1. Acquire catalog admin context
        ok = _wintrust_dll.CryptCATAdminAcquireContext2(
            ctypes.byref(h_cat_admin), None, None, None, 0,
        )
        if not ok or not h_cat_admin.value:
            return (_TRUST_E_NOSIGNATURE, None)

        # 2. Open the file for hashing
        h_file = _kernel32_dll.CreateFileW(
            filepath, _GENERIC_READ, _FILE_SHARE_READ,
            None, _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None,
        )
        if h_file == ctypes.wintypes.HANDLE(_INVALID_HANDLE_VALUE).value or not h_file:
            return (_TRUST_E_NOSIGNATURE, None)

        # 3. Get hash size
        hash_size = ctypes.wintypes.DWORD(0)
        _wintrust_dll.CryptCATAdminCalcHashFromFileHandle2(
            h_cat_admin, h_file, ctypes.byref(hash_size), None, 0,
        )
        if hash_size.value == 0:
            return (_TRUST_E_NOSIGNATURE, None)

        # 4. Calculate hash
        hash_buf = (ctypes.c_ubyte * hash_size.value)()
        ok = _wintrust_dll.CryptCATAdminCalcHashFromFileHandle2(
            h_cat_admin, h_file, ctypes.byref(hash_size), hash_buf, 0,
        )
        if not ok:
            return (_TRUST_E_NOSIGNATURE, None)

        # Close file — no longer needed
        _kernel32_dll.CloseHandle(h_file)
        h_file = ctypes.wintypes.HANDLE(0)

        # 5. Find catalog containing this hash
        prev_cat = ctypes.c_void_p(0)
        h_cat_info = ctypes.c_void_p(
            _wintrust_dll.CryptCATAdminEnumCatalogFromHash(
                h_cat_admin, hash_buf, hash_size, 0, ctypes.byref(prev_cat),
            )
        )
        if not h_cat_info.value:
            return (_TRUST_E_NOSIGNATURE, None)

        # 6. Get catalog file path
        cat_info = _CATALOG_INFO()
        cat_info.cbStruct = ctypes.sizeof(_CATALOG_INFO)
        ok = _wintrust_dll.CryptCATCatalogInfoFromContext(
            h_cat_info, ctypes.byref(cat_info), 0,
        )
        if not ok:
            return (_TRUST_E_NOSIGNATURE, None)

        # 7. Build member tag (hex string of hash)
        member_tag = "".join(f"{b:02X}" for b in hash_buf)

        # 8. Build WINTRUST_CATALOG_INFO for verification
        wt_cat = _WINTRUST_CATALOG_INFO()
        wt_cat.cbStruct = ctypes.sizeof(_WINTRUST_CATALOG_INFO)
        wt_cat.pcwszCatalogFilePath = cat_info.wszCatalogFile
        wt_cat.pcwszMemberTag = member_tag
        wt_cat.pcwszMemberFilePath = filepath
        wt_cat.hMemberFile = None
        wt_cat.pbCalculatedFileHash = hash_buf
        wt_cat.cbCalculatedFileHash = hash_size
        wt_cat.pcCatalogContext = None
        wt_cat.hCatAdmin = None

        # 9. Verify via WinVerifyTrust
        wd = _WINTRUST_DATA()
        wd.cbStruct = ctypes.sizeof(_WINTRUST_DATA)
        wd.dwUIChoice = _WTD_UI_NONE
        wd.fdwRevocationChecks = _WTD_REVOKE_NONE
        wd.dwUnionChoice = _WTD_CHOICE_CATALOG
        wd.pUnionData = ctypes.cast(ctypes.pointer(wt_cat), ctypes.c_void_p)
        wd.dwStateAction = _WTD_STATEACTION_VERIFY
        wd.hWVTStateData = None
        wd.dwProvFlags = _WTD_SAFER_FLAG | _WTD_CACHE_ONLY_URL_RETRIEVAL

        hr = _wintrust_dll.WinVerifyTrust(
            ctypes.c_void_p(_INVALID_HANDLE_VALUE),
            ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(wd),
        )
        return (hr, wd)

    finally:
        # Cleanup catalog handles
        if h_file and h_file != ctypes.wintypes.HANDLE(_INVALID_HANDLE_VALUE).value:
            try:
                _kernel32_dll.CloseHandle(h_file)
            except Exception:
                pass
        if h_cat_info.value:
            try:
                _wintrust_dll.CryptCATAdminReleaseCatalogContext(
                    h_cat_admin, h_cat_info, 0,
                )
            except Exception:
                pass
        if h_cat_admin.value:
            try:
                _wintrust_dll.CryptCATAdminReleaseContext(h_cat_admin, 0)
            except Exception:
                pass


def _extract_signer_name(state_data: ctypes.wintypes.HANDLE) -> str:
    """Extract the signer Common Name from WinVerifyTrust state data.

    Uses WTHelperProvDataFromStateData → WTHelperGetProvSignerFromChain
    → certificate chain → CertGetNameStringW.

    Args:
        state_data: hWVTStateData from a successful WTD_STATEACTION_VERIFY.

    Returns:
        Signer name string, or "Unknown" if extraction fails.
    """
    try:
        if not state_data:
            return "Unknown"

        prov_data = _wintrust_dll.WTHelperProvDataFromStateData(state_data)
        if not prov_data:
            return "Unknown"

        prov_signer = _wintrust_dll.WTHelperGetProvSignerFromChain(
            prov_data, 0, False, 0,
        )
        if not prov_signer:
            return "Unknown"

        # CRYPT_PROVIDER_SGNR: cbStruct(DWORD) + sftVerifyAsOf(FILETIME=8) +
        # csCertChain(DWORD) + pasCertChain(POINTER)
        # Offset to pasCertChain: 4 + 8 + 4 = 16 bytes
        # Read pasCertChain pointer
        pas_cert_chain_ptr = ctypes.c_void_p.from_address(prov_signer + 16)
        if not pas_cert_chain_ptr.value:
            return "Unknown"

        # CRYPT_PROVIDER_CERT: cbStruct(DWORD) + pCert(pointer)
        # pCert is at offset 4 (32-bit) or 8 (64-bit, due to alignment)
        cert_ptr_offset = ctypes.sizeof(ctypes.c_void_p)  # 8 on 64-bit
        cert_ctx = ctypes.c_void_p.from_address(
            pas_cert_chain_ptr.value + cert_ptr_offset
        )
        if not cert_ctx.value:
            return "Unknown"

        # Extract the simple display name (CN)
        buf = ctypes.create_unicode_buffer(256)
        chars = _crypt32_dll.CertGetNameStringW(
            cert_ctx.value, _CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, None, buf, 256,
        )
        if chars > 1:
            return buf.value

    except Exception:
        pass

    return "Unknown"


def _close_wintrust_state(wd: _WINTRUST_DATA) -> None:
    """Close WinVerifyTrust state data to release resources."""
    try:
        wd.dwStateAction = _WTD_STATEACTION_CLOSE
        _wintrust_dll.WinVerifyTrust(
            ctypes.c_void_p(_INVALID_HANDLE_VALUE),
            ctypes.byref(_WINTRUST_ACTION_GENERIC_VERIFY_V2),
            ctypes.byref(wd),
        )
    except Exception:
        pass


def _powershell_check_signature(filepath: str) -> dict:
    """Fallback: Check file signature via PowerShell Get-AuthenticodeSignature.

    Legacy method kept as fallback when ctypes WinVerifyTrust fails
    (e.g., corrupted wintrust.dll, unusual file format).

    Args:
        filepath: Absolute path to the file.

    Returns:
        {"signed": bool, "signer": str, "trusted": bool}
    """
    result = {"signed": False, "signer": "Unknown", "trusted": False}
    try:
        escaped_path = filepath.replace("'", "''")
        ps_cmd = (
            f"$s = Get-AuthenticodeSignature '{escaped_path}'; "
            f"$s.Status; '|'; "
            f"if ($s.SignerCertificate) {{ $s.SignerCertificate.Subject }} "
            f"else {{ 'NONE' }}"
        )
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=8,
            encoding="utf-8", errors="replace",
        )
        output = proc.stdout.strip()
        parts = output.split("|")

        if len(parts) >= 2:
            status = parts[0].strip()
            subject = parts[1].strip()

            if status in ("Valid", ""):
                result["signed"] = True

                signer = subject
                for part_s in subject.split(","):
                    part_s = part_s.strip()
                    if part_s.upper().startswith("CN="):
                        signer = part_s[3:].strip('"')
                        break

                result["signer"] = signer
                result["trusted"] = is_trusted_signer(signer)

    except (subprocess.TimeoutExpired, FileNotFoundError, OSError, Exception):
        pass

    return result


# ---- Main entry point ----

def check_file_signature(filepath: str) -> dict:
    """Check if a file is digitally signed.

    Verification order:
      1. ctypes WinVerifyTrust (embedded Authenticode) — ~0.1-1ms
      2. ctypes catalog verification (OS built-ins) — ~1-5ms
      3. PowerShell Get-AuthenticodeSignature fallback — ~200-800ms

    Args:
        filepath: Absolute path to the file to verify.

    Returns:
        {"signed": bool, "signer": str, "trusted": bool}
        Results are cached (LRU, max 2000 entries).
    """
    cached = _signature_cache.get(filepath)
    if cached is not None:
        return cached

    result = {"signed": False, "signer": "Unknown", "trusted": False}

    if not filepath or not os.path.isfile(filepath):
        _signature_cache.put(filepath, result)
        return result

    if _WINTRUST_AVAILABLE:
        # --- Attempt 1: Embedded Authenticode via ctypes ---
        try:
            hr, wd = _wintrust_verify_embedded(filepath)
            if hr == 0:
                signer = _extract_signer_name(wd.hWVTStateData)
                _close_wintrust_state(wd)
                result = {
                    "signed": True,
                    "signer": signer,
                    "trusted": is_trusted_signer(signer),
                }
                _signature_cache.put(filepath, result)
                return result
            _close_wintrust_state(wd)
        except Exception:
            pass

        # --- Attempt 2: Catalog-signed file via ctypes ---
        try:
            hr, wd = _catalog_verify(filepath)
            if hr == 0 and wd is not None:
                signer = _extract_signer_name(wd.hWVTStateData)
                _close_wintrust_state(wd)
                result = {
                    "signed": True,
                    "signer": signer,
                    "trusted": is_trusted_signer(signer),
                }
                _signature_cache.put(filepath, result)
                return result
            if wd is not None:
                _close_wintrust_state(wd)
        except Exception:
            pass

    # --- Attempt 3: PowerShell fallback ---
    try:
        result = _powershell_check_signature(filepath)
    except Exception:
        pass

    _signature_cache.put(filepath, result)
    return result


# ---------------------------------------------------------------------------
# Trusted Vendor / Known-Safe Recognition
# ---------------------------------------------------------------------------
TRUSTED_SIGNERS = {
    "microsoft": True,
    "microsoft corporation": True,
    "microsoft windows": True,
    "microsoft code signing pca": True,
    "google": True,
    "google llc": True,
    "google inc": True,
    "apple": True,
    "apple inc": True,
    "mozilla": True,
    "mozilla corporation": True,
    "python software foundation": True,
    "node.js foundation": True,
    "github": True,
    "github, inc": True,
    "jetbrains": True,
    "jetbrains s.r.o.": True,
    "docker": True,
    "docker inc": True,
    "oracle": True,
    "oracle america": True,
    "vmware": True,
    "vmware, inc": True,
    "cisco": True,
    "cisco systems": True,
    "adobe": True,
    "adobe inc": True,
    "amazon": True,
    "amazon.com": True,
    "slack technologies": True,
    "zoom video communications": True,
    "brave software": True,
    "opera software": True,
    "1password": True,
    "bitwarden inc": True,
    "anysphere": True,  # Cursor IDE
    "cursor": True,
    # Network/Security tools
    "wireshark": True,
    "wireshark foundation": True,
    "nmap": True,
    "insecure.org": True,
    # Common software vendors
    "valve": True,
    "valve corp.": True,
    "epic games": True,
    "riot games": True,
    "riot games, inc": True,
    "logitech": True,
    "logitech inc": True,
    "corsair": True,
    "razer": True,
    "razer inc": True,
    "nvidia": True,
    "nvidia corporation": True,
    "amd": True,
    "advanced micro devices": True,
    "intel": True,
    "intel corporation": True,
    "realtek": True,
    "realtek semiconductor": True,
    # AV / EDR / Security vendors (binaries often in non-standard paths)
    "crowdstrike": True,
    "crowdstrike, inc.": True,
    "sentinelone": True,
    "sophos": True,
    "sophos ltd": True,
    "symantec": True,
    "symantec corporation": True,
    "broadcom": True,
    "broadcom inc.": True,
    "mcafee": True,
    "mcafee, llc": True,
    "trellix": True,
    "eset": True,
    "eset, spol. s r.o.": True,
    "kaspersky": True,
    "kaspersky lab": True,
    "palo alto networks": True,
    "fortinet": True,
    "fortinet, inc": True,
    "malwarebytes": True,
    "malwarebytes inc": True,
    "trend micro": True,
    "trend micro, inc.": True,
    "bitdefender": True,
    "bitdefender srl": True,
    "avast software": True,
    "avg technologies": True,
    "carbon black": True,    # VMware Carbon Black
    "cybereason": True,
    # OEM / Hardware vendors
    "dell": True,
    "dell inc": True,
    "dell technologies": True,
    "hp inc.": True,
    "hewlett-packard": True,
    "hewlett packard enterprise": True,
    "lenovo": True,
    "lenovo (beijing)": True,
    "samsung electronics": True,
    "asus": True,
    "asustek computer": True,
    # Common enterprise / productivity (AppData runners)
    "dropbox": True,
    "dropbox, inc": True,
    "salesforce": True,
    "salesforce.com": True,
    "atlassian": True,
    "atlassian pty ltd": True,
    "notion labs": True,
    "spotify ab": True,
    "signal": True,
    "signal messenger, llc": True,
    "discord inc.": True,
}

# Known developer tool process names (lowercase)
KNOWN_DEV_TOOL_PROCESSES = {
    "code.exe", "cursor.exe", "antigravity.exe",
    "node.exe", "python.exe", "pythonw.exe", "python3.exe",
    "java.exe", "javaw.exe",
    "git.exe", "git-remote-https.exe",
    "language_server_windows_x64.exe", "language_server.exe",
    "gopls.exe", "rust-analyzer.exe", "clangd.exe",
    "typescript-language-server.exe", "eslint.exe",
    "electron.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "notion.exe", "claude.exe",
    "slack.exe", "discord.exe", "spotify.exe",
    "idea64.exe", "pycharm64.exe", "webstorm64.exe", "goland64.exe",
    "docker.exe", "docker-compose.exe",
    "npm.cmd", "npx.cmd", "yarn.exe", "pnpm.exe",
    "pip.exe", "pip3.exe", "conda.exe",
    "dotnet.exe", "msbuild.exe",
    "terraform.exe", "kubectl.exe",
    "powershell.exe",  # Note: flagged only in specific suspicious contexts, not blanket
}

# Known developer tool path patterns (lowercase)
KNOWN_DEV_TOOL_PATHS = [
    "\\programs\\python\\",
    "\\programs\\node\\",
    "\\cursor\\",
    "\\antigravity\\",
    "\\visual studio code\\",
    "\\vs code\\",
    "\\vscode\\",
    "\\jetbrains\\",
    "\\docker\\",
    "\\git\\",
    "\\programs\\git\\",
    "\\android studio\\",
    "\\sublime text\\",
    "\\notepad++\\",
    "\\programs\\microsoft vs code\\",
    "\\electron\\",
]


def is_trusted_signer(signer: str) -> bool:
    """Check if a signer is a known trusted vendor.

    Uses exact match first, then prefix match (trusted + space) to catch
    extended names like "Microsoft Windows Publisher" matching "microsoft windows".
    Never uses substring matching to prevent spoofing (e.g., "notmicrosoft corp").
    """
    if not signer or signer == "Unknown":
        return False
    signer_lower = signer.lower().strip('"')
    # Direct exact match
    if signer_lower in TRUSTED_SIGNERS:
        return True
    # Prefix match: "microsoft windows publisher" starts with "microsoft windows "
    for trusted in TRUSTED_SIGNERS:
        if signer_lower.startswith(trusted + " "):
            return True
    return False


def is_known_dev_tool(proc_name: str, proc_path: str = "") -> bool:
    """Check if a process is a known developer tool."""
    name_lower = proc_name.lower()
    path_lower = proc_path.lower()

    if name_lower in KNOWN_DEV_TOOL_PROCESSES:
        return True

    for pattern in KNOWN_DEV_TOOL_PATHS:
        if pattern in path_lower:
            return True

    return False


def is_suspicious_userland_path(path: str) -> bool:
    """Check if a file path is in a user-writable 'suspicious' location.
    Returns True ONLY if it's not a known developer tool path."""
    path_lower = path.lower()
    suspicious_locs = [
        "\\appdata\\", "\\temp\\", "\\tmp\\",
        "\\downloads\\", "\\users\\public\\",
    ]
    if not any(loc in path_lower for loc in suspicious_locs):
        return False

    # Exempt known developer tool paths
    for dev_path in KNOWN_DEV_TOOL_PATHS:
        if dev_path in path_lower:
            return False

    return True


# ---------------------------------------------------------------------------
# System Processes — single source of truth
# Shared by process_scanner.py and memory_scanner.py.
# Add new Windows system processes here so both modules stay in sync.
# ---------------------------------------------------------------------------
SYSTEM_PROCESSES = {
    "system", "system idle process", "registry", "memory compression",
    "smss.exe", "csrss.exe", "wininit.exe", "winlogon.exe",
    "lsass.exe", "services.exe", "svchost.exe", "dwm.exe",
    "taskhost.exe", "taskhostw.exe", "sihost.exe", "explorer.exe",
    "runtimebroker.exe", "searchui.exe",
    "securityhealthservice.exe", "securityhealthsystray.exe",
    "msmpeng.exe", "mpcmdrun.exe", "mpdefendercoreservice.exe",
    "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "ctfmon.exe", "fontdrvhost.exe", "spoolsv.exe",
    "searchindexer.exe", "dllhost.exe", "conhost.exe",
    "audiodg.exe", "wmiprvse.exe", "wuauclt.exe",
}


# ---------------------------------------------------------------------------
# Windows Defender / OS Native Path Whitelist
# ---------------------------------------------------------------------------
OS_NATIVE_PATHS = [
    "c:\\windows\\",
    "c:\\program files\\",
    "c:\\program files (x86)\\",
    "c:\\programdata\\microsoft\\windows defender\\",
    "c:\\programdata\\microsoft\\windows\\",
    "c:\\programdata\\microsoft\\windows security health\\",
]


def is_os_native_path(path: str) -> bool:
    """Check if a binary path is an OS-native or Microsoft-managed location."""
    path_lower = path.lower()
    return any(path_lower.startswith(p) for p in OS_NATIVE_PATHS)


# ---------------------------------------------------------------------------
# I/O Throttling Utilities
# ---------------------------------------------------------------------------
class IOThrottle:
    """
    Simple I/O throttle that inserts micro-sleeps to avoid saturating disk I/O.
    Tracks operations per batch and yields periodically.
    """

    def __init__(self, ops_per_batch: int = 50, sleep_seconds: float = 0.05):
        self.ops_per_batch = ops_per_batch
        self.sleep_seconds = sleep_seconds
        self._counter = 0

    def tick(self):
        """Call after each I/O operation. Sleeps when batch limit is reached."""
        self._counter += 1
        if self._counter >= self.ops_per_batch:
            time.sleep(self.sleep_seconds)
            self._counter = 0


# ---------------------------------------------------------------------------
# Admin Check
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    """Check if the current process has administrator privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Console Helpers
# ---------------------------------------------------------------------------
_CYAN = "\x1b[96m"
_RESET = "\x1b[0m"

CROW_ART = (
    "\n"
    '                                  .-----.\n'
    "                                 /       \\\n"
    "                                |  {eye}      |\n"
    "                         _____  |         /\n"
    "                       <`_____\\\\  \\       /\n"
    "                                `.   _.'\n"
    '                              ___/ `"` \\___\n'
    "                            .'    .---.    `.\n"
    "                           /    .'     `.    \\\n"
    "                          /   .'  CORVUS `.   \\\n"
    "                          |  /             \\  |\n"
    "                           \\(    _ _ _ _    )/\n"
    "                            `\\--/ / / / \\--'`\n"
    "                              \\_/ / / / /\n"
    "                               /_/_/_/_/\n"
    "                              / / / / /\n"
    "                             '-'-'-'-'\n"
    "\n"
).format(eye=_CYAN + "@" + _RESET)

BANNER_TEXT = r"""
       ____    ___    ____   __     __  _   _   ____
      / ___|  / _ \  |  _ \  \ \   / / | | | | / ___|
     | |     | | | | | |_) |  \ \ / /  | | | | \___ \
     | |___  | |_| | |  _ <    \ V /   | |_| |  ___) |
      \____|  \___/  |_| \_\    \_/     \___/  |____/

        E N D P O I N T   T H R E A T   D E T E C T I O N
"""

BANNER = """
  +============================================================+
  |                      C O R V U S                            |
  |            Endpoint Threat Detection Scanner                |
  +============================================================+
"""


def print_startup_banner(animate: bool = True) -> None:
    """Print the startup banner with optional typing animation."""
    if not animate:
        print(CROW_ART)
        print(BANNER_TEXT)
        return

    # Typing animation for crow art
    lines = CROW_ART.rstrip("\n").split("\n")
    for line in lines:
        print(line)
        time.sleep(0.02)

    # Faster reveal for the text banner
    text_lines = BANNER_TEXT.rstrip("\n").split("\n")
    for line in text_lines:
        print(line)
        time.sleep(0.04)

    # Separator line
    print("  " + "-" * 60)
    print()


def print_section(title: str):
    print(f"\n{'='*60}")
    print(f"  [*] {title}")
    print(f"{'='*60}")


def print_finding(finding: Finding):
    risk_label = finding.risk.value
    print(f"  [{risk_label}] {finding.title}")
