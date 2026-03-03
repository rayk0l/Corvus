"""
Tests for credential scanner registry expansion — Sprint 3.2.

Tests cover:
  - _scan_registry_credentials() returns List[Finding]
  - All findings have correct module name and MITRE IDs
  - All findings contain "NOT read" note (never reads credential values)
  - _REGISTRY_CREDENTIAL_PATHS data structure integrity
  - FileZilla sitemanager.xml detection
  - Hive map lazy initialization
  - Finding contract validation
"""

import os
import sys
import tempfile
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner_core.models import Finding, RiskLevel

pytestmark = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Registry credential checks require Windows",
)


class TestRegistryCredentialPaths:
    """Validate the _REGISTRY_CREDENTIAL_PATHS data structure."""

    def test_paths_have_correct_structure(self):
        from scanners.credential_scanner import _REGISTRY_CREDENTIAL_PATHS
        for entry in _REGISTRY_CREDENTIAL_PATHS:
            assert len(entry) == 5, f"Entry must have 5 elements: {entry}"
            hive, path, app, desc, check_type = entry
            assert hive in ("HKCU", "HKLM"), f"Invalid hive: {hive}"
            assert isinstance(path, str) and len(path) > 0
            assert isinstance(app, str) and len(app) > 0
            assert isinstance(desc, str) and len(desc) > 0
            assert check_type in ("sessions", "key_exists"), f"Invalid check_type: {check_type}"

    def test_putty_path_present(self):
        from scanners.credential_scanner import _REGISTRY_CREDENTIAL_PATHS
        apps = [entry[2] for entry in _REGISTRY_CREDENTIAL_PATHS]
        assert "PuTTY" in apps

    def test_winscp_path_present(self):
        from scanners.credential_scanner import _REGISTRY_CREDENTIAL_PATHS
        apps = [entry[2] for entry in _REGISTRY_CREDENTIAL_PATHS]
        assert "WinSCP" in apps

    def test_vnc_paths_present(self):
        from scanners.credential_scanner import _REGISTRY_CREDENTIAL_PATHS
        apps = [entry[2] for entry in _REGISTRY_CREDENTIAL_PATHS]
        assert "RealVNC" in apps or "TightVNC" in apps

    def test_sessions_type_for_putty_winscp(self):
        """PuTTY and WinSCP should use 'sessions' check type."""
        from scanners.credential_scanner import _REGISTRY_CREDENTIAL_PATHS
        for hive, path, app, desc, check_type in _REGISTRY_CREDENTIAL_PATHS:
            if app in ("PuTTY", "WinSCP"):
                assert check_type == "sessions", f"{app} should use 'sessions' check"

    def test_key_exists_for_vnc(self):
        """VNC entries should use 'key_exists' check type."""
        from scanners.credential_scanner import _REGISTRY_CREDENTIAL_PATHS
        for hive, path, app, desc, check_type in _REGISTRY_CREDENTIAL_PATHS:
            if "VNC" in app:
                assert check_type == "key_exists", f"{app} should use 'key_exists' check"


class TestHiveMap:
    """Test hive map initialization."""

    def test_hive_map_returns_dict(self):
        from scanners.credential_scanner import _get_hive_map
        hive_map = _get_hive_map()
        assert isinstance(hive_map, dict)

    def test_hive_map_has_hkcu_and_hklm(self):
        from scanners.credential_scanner import _get_hive_map
        hive_map = _get_hive_map()
        assert "HKCU" in hive_map
        assert "HKLM" in hive_map

    def test_hive_map_values_are_int(self):
        """winreg hive constants are integers."""
        from scanners.credential_scanner import _get_hive_map
        hive_map = _get_hive_map()
        for key, val in hive_map.items():
            assert isinstance(val, int), f"Hive {key} value should be int, got {type(val)}"


class TestScanRegistryCredentials:
    """Integration tests for _scan_registry_credentials()."""

    def test_returns_list(self):
        from scanners.credential_scanner import _scan_registry_credentials
        result = _scan_registry_credentials()
        assert isinstance(result, list)

    def test_all_findings_are_finding_instances(self):
        from scanners.credential_scanner import _scan_registry_credentials
        result = _scan_registry_credentials()
        for f in result:
            assert isinstance(f, Finding)

    def test_all_findings_have_correct_module(self):
        from scanners.credential_scanner import _scan_registry_credentials
        result = _scan_registry_credentials()
        for f in result:
            assert f.module == "Credential Scanner"

    def test_all_findings_have_mitre_id(self):
        from scanners.credential_scanner import _scan_registry_credentials
        result = _scan_registry_credentials()
        for f in result:
            assert f.mitre_id.startswith("T155"), (
                f"MITRE ID should be T1552.x, got {f.mitre_id}"
            )

    def test_all_findings_note_not_read(self):
        """Every finding must confirm credential values were NOT read."""
        from scanners.credential_scanner import _scan_registry_credentials
        result = _scan_registry_credentials()
        for f in result:
            note = f.details.get("note", "")
            assert "NOT read" in note, (
                f"Finding must state values NOT read: {f.title}"
            )

    def test_findings_have_application_name(self):
        from scanners.credential_scanner import _scan_registry_credentials
        result = _scan_registry_credentials()
        for f in result:
            assert "application" in f.details, f"Missing application in details: {f.title}"

    def test_findings_have_registry_path_or_file_path(self):
        from scanners.credential_scanner import _scan_registry_credentials
        result = _scan_registry_credentials()
        for f in result:
            has_reg = "registry_path" in f.details
            has_file = "path" in f.details
            assert has_reg or has_file, f"Missing path in details: {f.title}"


class TestFileZillaDetection:
    """Test FileZilla sitemanager.xml detection."""

    def test_filezilla_detected_when_present(self):
        """If sitemanager.xml exists and non-empty, it should be detected."""
        from scanners.credential_scanner import _scan_registry_credentials
        appdata = os.environ.get("APPDATA", "")
        fz_path = os.path.join(appdata, "FileZilla", "sitemanager.xml")

        result = _scan_registry_credentials()
        fz_findings = [f for f in result if "FileZilla" in f.title]

        if os.path.isfile(fz_path) and os.path.getsize(fz_path) > 0:
            assert len(fz_findings) >= 1, "FileZilla sitemanager.xml exists but not detected"
        # If FileZilla not installed, no finding expected — test still passes

    def test_filezilla_finding_has_correct_mitre(self):
        """FileZilla is file-based → T1552.001 (not .002)."""
        from scanners.credential_scanner import _scan_registry_credentials
        result = _scan_registry_credentials()
        fz_findings = [f for f in result if "FileZilla" in f.title]
        for f in fz_findings:
            assert f.mitre_id == "T1552.001"


class TestFullScanIntegration:
    """Verify the full scan() function still works with registry additions."""

    def test_scan_returns_list(self):
        from scanners.credential_scanner import scan
        result = scan()
        assert isinstance(result, list)
        for f in result:
            assert isinstance(f, Finding)
