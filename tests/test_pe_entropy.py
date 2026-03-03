"""
Tests for PE header + entropy analysis — Sprint 3.1.

Tests cover:
  - Shannon entropy calculation (unit)
  - PE header parsing with synthetic minimal PE binaries
  - Packer section name detection (UPX, VMProtect, Themida, etc.)
  - RWX section characteristic detection
  - High entropy section detection
  - Non-PE file handling (graceful empty list)
  - Truncated / malformed PE handling
  - Finding contract validation (module, risk, mitre_id)
  - Data structure integrity (PACKER_SECTION_NAMES, PE_EXTENSIONS)
"""

import os
import sys
import math
import struct
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner_core.models import Finding, RiskLevel
from scanners.file_scanner import (
    _calculate_shannon_entropy,
    _analyze_pe_headers,
    PACKER_SECTION_NAMES,
    PE_EXTENSIONS,
    _IMAGE_SCN_MEM_EXECUTE,
    _IMAGE_SCN_MEM_WRITE,
)


# ---------------------------------------------------------------------------
# Helpers — synthetic PE binary construction
# ---------------------------------------------------------------------------

def _build_dos_header(e_lfanew: int = 0x80) -> bytes:
    """Build a minimal DOS header with MZ magic and e_lfanew pointer."""
    header = bytearray(64)
    header[0:2] = b"MZ"
    struct.pack_into("<I", header, 0x3C, e_lfanew)
    # Pad to e_lfanew
    if e_lfanew > 64:
        header.extend(b"\x00" * (e_lfanew - 64))
    return bytes(header)


def _build_pe_header(
    num_sections: int = 1,
    optional_header_size: int = 0,
) -> bytes:
    """Build PE signature + COFF header."""
    buf = bytearray()
    buf.extend(b"PE\x00\x00")  # PE signature
    # COFF header (20 bytes)
    coff = bytearray(20)
    struct.pack_into("<H", coff, 2, num_sections)  # NumberOfSections
    struct.pack_into("<H", coff, 16, optional_header_size)  # SizeOfOptionalHeader
    buf.extend(coff)
    # Optional header (if any)
    if optional_header_size > 0:
        buf.extend(b"\x00" * optional_header_size)
    return bytes(buf)


def _build_section_entry(
    name: str = ".text",
    raw_size: int = 512,
    raw_ptr: int = 0x200,
    characteristics: int = 0x60000020,  # CODE | EXECUTE | READ
) -> bytes:
    """Build a 40-byte PE section table entry."""
    entry = bytearray(40)
    name_bytes = name.encode("ascii")[:8]
    entry[0:len(name_bytes)] = name_bytes
    struct.pack_into("<I", entry, 16, raw_size)    # SizeOfRawData
    struct.pack_into("<I", entry, 20, raw_ptr)     # PointerToRawData
    struct.pack_into("<I", entry, 36, characteristics)
    return bytes(entry)


def _build_minimal_pe(
    sections: list = None,
    section_data: dict = None,
) -> bytes:
    """Build a complete minimal PE binary with given sections.

    Args:
        sections: List of dicts with keys: name, raw_size, characteristics.
        section_data: Dict mapping section index to raw bytes for that section.
    """
    if sections is None:
        sections = [{"name": ".text", "raw_size": 512, "characteristics": 0x60000020}]
    if section_data is None:
        section_data = {}

    e_lfanew = 0x80
    dos = _build_dos_header(e_lfanew)
    pe = _build_pe_header(num_sections=len(sections))

    # Calculate raw pointers — section data starts after all headers
    header_end = e_lfanew + 4 + 20 + (40 * len(sections))
    # Align to 0x200 boundary
    data_start = ((header_end + 0x1FF) // 0x200) * 0x200

    section_table = bytearray()
    current_ptr = data_start
    section_ptrs = []
    for sec in sections:
        raw_size = sec.get("raw_size", 512)
        chars = sec.get("characteristics", 0x60000020)
        entry = _build_section_entry(
            name=sec["name"],
            raw_size=raw_size,
            raw_ptr=current_ptr,
            characteristics=chars,
        )
        section_table.extend(entry)
        section_ptrs.append((current_ptr, raw_size))
        current_ptr += raw_size

    # Assemble: DOS header + PE header + section table + padding + section data
    binary = bytearray(dos)
    binary.extend(pe)
    binary.extend(section_table)

    # Pad to data_start
    if len(binary) < data_start:
        binary.extend(b"\x00" * (data_start - len(binary)))

    # Write section data
    for i, (ptr, size) in enumerate(section_ptrs):
        if i in section_data:
            data = section_data[i][:size]
            # Pad if shorter
            data = data + b"\x00" * (size - len(data))
        else:
            # Default: zero-filled
            data = b"\x00" * size
        # Ensure binary is long enough
        while len(binary) < ptr:
            binary.extend(b"\x00")
        binary[ptr:ptr + size] = data

    return bytes(binary)


def _write_temp_pe(pe_bytes: bytes, suffix: str = ".exe") -> str:
    """Write PE bytes to a temp file, return path."""
    fd, path = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, pe_bytes)
    finally:
        os.close(fd)
    return path


# ---------------------------------------------------------------------------
# Shannon Entropy Unit Tests
# ---------------------------------------------------------------------------

class TestShannonEntropy:
    def test_empty_data_returns_zero(self):
        assert _calculate_shannon_entropy(b"") == 0.0

    def test_single_byte_returns_zero(self):
        # All identical bytes → entropy = 0
        assert _calculate_shannon_entropy(b"\x00" * 1024) == 0.0

    def test_two_equal_values(self):
        # 50/50 distribution → entropy = 1.0
        data = b"\x00\x01" * 512
        entropy = _calculate_shannon_entropy(data)
        assert abs(entropy - 1.0) < 0.01

    def test_random_bytes_high_entropy(self):
        # All 256 byte values equally distributed → entropy ≈ 8.0
        data = bytes(range(256)) * 100
        entropy = _calculate_shannon_entropy(data)
        assert entropy > 7.9

    def test_english_text_moderate_entropy(self):
        # English text typically has entropy around 3.5-5.0
        text = b"The quick brown fox jumps over the lazy dog. " * 50
        entropy = _calculate_shannon_entropy(text)
        assert 3.0 < entropy < 6.0

    def test_packed_data_high_entropy(self):
        # Simulate packed/compressed data (pseudo-random distribution)
        import hashlib
        data = b""
        for i in range(100):
            data += hashlib.sha256(str(i).encode()).digest()
        entropy = _calculate_shannon_entropy(data)
        assert entropy > 7.0

    def test_return_type_is_float(self):
        assert isinstance(_calculate_shannon_entropy(b"\x00"), float)

    def test_entropy_range(self):
        # Entropy must be 0.0-8.0 for any input
        for data in [b"\x00", b"\xff" * 100, bytes(range(256)), b"AAAA"]:
            e = _calculate_shannon_entropy(data)
            assert 0.0 <= e <= 8.0


# ---------------------------------------------------------------------------
# PE Header Analysis Tests
# ---------------------------------------------------------------------------

class TestPEHeaderAnalysis:
    def test_non_pe_file_returns_empty(self):
        """Non-PE files (e.g., text) should return empty list."""
        fd, path = tempfile.mkstemp(suffix=".exe")
        try:
            os.write(fd, b"This is not a PE file at all.")
            os.close(fd)
            findings = _analyze_pe_headers(path)
            assert findings == []
        finally:
            os.unlink(path)

    def test_truncated_dos_header(self):
        """File shorter than 64 bytes (DOS header) → empty list."""
        fd, path = tempfile.mkstemp(suffix=".exe")
        try:
            os.write(fd, b"MZ" + b"\x00" * 10)
            os.close(fd)
            assert _analyze_pe_headers(path) == []
        finally:
            os.unlink(path)

    def test_bad_pe_signature(self):
        """DOS header OK but PE signature is wrong → empty list."""
        dos = _build_dos_header(0x80)
        binary = bytearray(dos)
        binary.extend(b"XX\x00\x00")  # Bad signature
        fd, path = tempfile.mkstemp(suffix=".exe")
        try:
            os.write(fd, bytes(binary))
            os.close(fd)
            assert _analyze_pe_headers(path) == []
        finally:
            os.unlink(path)

    def test_nonexistent_file(self):
        """Non-existent file → empty list (OSError handled)."""
        assert _analyze_pe_headers("C:\\nonexistent_pe_file.exe") == []

    def test_normal_pe_no_findings(self):
        """Normal PE with standard .text section → no findings."""
        pe = _build_minimal_pe(
            sections=[{"name": ".text", "raw_size": 512, "characteristics": 0x60000020}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            assert findings == []
        finally:
            os.unlink(path)


class TestPackerDetection:
    def test_upx0_section_detected(self):
        """PE with UPX0 section → HIGH finding."""
        pe = _build_minimal_pe(
            sections=[
                {"name": "UPX0", "raw_size": 512, "characteristics": 0xE0000040},
                {"name": "UPX1", "raw_size": 512, "characteristics": 0xE0000040},
            ],
            section_data={0: b"\x00" * 512, 1: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            packer_findings = [f for f in findings if "Packed executable" in f.title]
            assert len(packer_findings) == 1
            assert packer_findings[0].risk == RiskLevel.HIGH
            assert "UPX0" in packer_findings[0].description.lower() or \
                   "upx0" in str(packer_findings[0].details.get("packer_sections", []))
        finally:
            os.unlink(path)

    def test_vmp_section_detected(self):
        """PE with .vmp0 section → packer finding."""
        pe = _build_minimal_pe(
            sections=[{"name": ".vmp0", "raw_size": 512, "characteristics": 0xE0000040}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            packer_findings = [f for f in findings if "Packed executable" in f.title]
            assert len(packer_findings) == 1
            assert ".vmp0" in str(packer_findings[0].details.get("packer_sections", []))
        finally:
            os.unlink(path)

    def test_themida_section_detected(self):
        """PE with .themida section → packer finding."""
        pe = _build_minimal_pe(
            sections=[{"name": ".themida", "raw_size": 512, "characteristics": 0xE0000040}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            assert any("Packed executable" in f.title for f in findings)
        finally:
            os.unlink(path)

    def test_enigma_section_detected(self):
        pe = _build_minimal_pe(
            sections=[{"name": ".enigma", "raw_size": 512, "characteristics": 0xE0000040}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            assert any("Packed executable" in f.title for f in findings)
        finally:
            os.unlink(path)

    def test_packer_finding_mitre_id(self):
        """Packer findings must have MITRE T1027.002."""
        pe = _build_minimal_pe(
            sections=[{"name": "UPX0", "raw_size": 512, "characteristics": 0xE0000040}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            for f in findings:
                assert f.mitre_id == "T1027.002"
        finally:
            os.unlink(path)

    def test_packer_finding_module_name(self):
        """Packer findings must have module='File Scanner'."""
        pe = _build_minimal_pe(
            sections=[{"name": "UPX0", "raw_size": 512, "characteristics": 0xE0000040}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            for f in findings:
                assert f.module == "File Scanner"
        finally:
            os.unlink(path)


class TestHighEntropyDetection:
    def test_high_entropy_section_detected(self):
        """Section with random data (entropy > 7.0) → MEDIUM finding."""
        import hashlib
        # Generate high-entropy data
        high_entropy_data = b""
        for i in range(64):
            high_entropy_data += hashlib.sha256(str(i).encode()).digest()

        pe = _build_minimal_pe(
            sections=[{"name": ".rsrc", "raw_size": len(high_entropy_data),
                       "characteristics": 0x40000040}],
            section_data={0: high_entropy_data},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            entropy_findings = [f for f in findings if "High-entropy" in f.title]
            assert len(entropy_findings) == 1
            assert entropy_findings[0].risk == RiskLevel.MEDIUM
        finally:
            os.unlink(path)

    def test_low_entropy_section_no_finding(self):
        """Section with zeros (entropy ≈ 0) → no entropy finding."""
        pe = _build_minimal_pe(
            sections=[{"name": ".text", "raw_size": 1024, "characteristics": 0x60000020}],
            section_data={0: b"\x00" * 1024},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            entropy_findings = [f for f in findings if "High-entropy" in f.title]
            assert len(entropy_findings) == 0
        finally:
            os.unlink(path)

    def test_entropy_finding_has_section_values(self):
        """Entropy finding details should include section names and values."""
        import hashlib
        data = b""
        for i in range(64):
            data += hashlib.sha256(str(i).encode()).digest()

        pe = _build_minimal_pe(
            sections=[{"name": ".code", "raw_size": len(data),
                       "characteristics": 0x60000020}],
            section_data={0: data},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            entropy_findings = [f for f in findings if "High-entropy" in f.title]
            assert len(entropy_findings) == 1
            details = entropy_findings[0].details
            assert "high_entropy_sections" in details
            assert ".code" in details["high_entropy_sections"]
        finally:
            os.unlink(path)


class TestRWXDetection:
    def test_rwx_section_detected(self):
        """Section with RWX permissions → MEDIUM finding."""
        rwx_flags = _IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_MEM_WRITE | 0x40000000  # +READ
        pe = _build_minimal_pe(
            sections=[{"name": ".text", "raw_size": 512, "characteristics": rwx_flags}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            rwx_findings = [f for f in findings if "RWX" in f.title]
            assert len(rwx_findings) == 1
            assert rwx_findings[0].risk == RiskLevel.MEDIUM
        finally:
            os.unlink(path)

    def test_rwx_not_reported_with_packer(self):
        """If packer section found, RWX should NOT be reported (avoid double-flag)."""
        rwx_flags = _IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_MEM_WRITE | 0x40000000
        pe = _build_minimal_pe(
            sections=[{"name": "UPX0", "raw_size": 512, "characteristics": rwx_flags}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            rwx_findings = [f for f in findings if "RWX" in f.title]
            packer_findings = [f for f in findings if "Packed" in f.title]
            assert len(packer_findings) >= 1
            assert len(rwx_findings) == 0  # Suppressed when packer detected
        finally:
            os.unlink(path)

    def test_execute_only_no_finding(self):
        """Section with only EXECUTE (no WRITE) → no RWX finding."""
        pe = _build_minimal_pe(
            sections=[{"name": ".text", "raw_size": 512,
                       "characteristics": _IMAGE_SCN_MEM_EXECUTE | 0x40000000}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            rwx_findings = [f for f in findings if "RWX" in f.title]
            assert len(rwx_findings) == 0
        finally:
            os.unlink(path)


class TestDataStructures:
    def test_packer_names_are_lowercase(self):
        """All packer section names must be lowercase."""
        for name in PACKER_SECTION_NAMES:
            assert name == name.lower(), f"Packer name '{name}' is not lowercase"

    def test_pe_extensions_include_exe_dll(self):
        """PE_EXTENSIONS must include .exe and .dll at minimum."""
        assert ".exe" in PE_EXTENSIONS
        assert ".dll" in PE_EXTENSIONS

    def test_packer_names_have_upx(self):
        """At minimum, UPX packer should be detected."""
        assert "upx0" in PACKER_SECTION_NAMES
        assert "upx1" in PACKER_SECTION_NAMES

    def test_packer_names_have_vmprotect(self):
        """VMProtect packer should be detected."""
        assert ".vmp0" in PACKER_SECTION_NAMES

    def test_packer_names_have_themida(self):
        assert ".themida" in PACKER_SECTION_NAMES


class TestFindingContract:
    def test_all_findings_have_required_fields(self):
        """All PE findings must satisfy Finding contract."""
        pe = _build_minimal_pe(
            sections=[
                {"name": "UPX0", "raw_size": 512,
                 "characteristics": _IMAGE_SCN_MEM_EXECUTE | _IMAGE_SCN_MEM_WRITE | 0x40000000},
            ],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe)
        try:
            findings = _analyze_pe_headers(path)
            for f in findings:
                assert isinstance(f, Finding)
                assert f.module == "File Scanner"
                assert isinstance(f.risk, RiskLevel)
                assert f.title
                assert f.description
                assert f.mitre_id == "T1027.002"
                assert f.remediation
        finally:
            os.unlink(path)

    def test_dll_extension_works(self):
        """_analyze_pe_headers works on .dll files too."""
        pe = _build_minimal_pe(
            sections=[{"name": "UPX0", "raw_size": 512, "characteristics": 0xE0000040}],
            section_data={0: b"\x00" * 512},
        )
        path = _write_temp_pe(pe, suffix=".dll")
        try:
            findings = _analyze_pe_headers(path)
            assert any("Packed executable" in f.title for f in findings)
        finally:
            os.unlink(path)
