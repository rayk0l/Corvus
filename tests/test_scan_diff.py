"""
Scan diff / baseline comparison tests — Sprint 3.3.

Tests for _compute_diff() in main.py: comparing current findings against
a previous JSON report to identify NEW, RESOLVED, and UNCHANGED findings.
"""

import os
import sys
import json
import pytest
import tempfile

# Ensure src/ is on path so main resolves correctly
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner_core.models import Finding, RiskLevel
from main import _compute_diff


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(module: str, title: str, risk: RiskLevel = RiskLevel.INFO,
                  description: str = "test", mitre_id: str = "") -> Finding:
    """Create a Finding instance for testing."""
    return Finding(
        module=module,
        risk=risk,
        title=title,
        description=description,
        mitre_id=mitre_id,
    )


def _write_prev_report(findings: list, tmp_dir: str,
                       risk_score: int = 80,
                       scan_time: str = "2025-12-01T10:00:00") -> str:
    """Write a synthetic previous JSON report and return its path."""
    data = {
        "scanner": "Corvus",
        "scan_time": scan_time,
        "risk_score": risk_score,
        "findings": [
            {
                "module": f["module"],
                "risk": f["risk"],
                "title": f["title"],
                "description": f.get("description", ""),
                "mitre_id": f.get("mitre_id", ""),
            }
            for f in findings
        ],
    }
    path = os.path.join(tmp_dir, "prev_report.json")
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, ensure_ascii=False)
    return path


# ---------------------------------------------------------------------------
# Tests — basic scenarios
# ---------------------------------------------------------------------------

class TestComputeDiffBasic:
    """Test _compute_diff with straightforward scenarios."""

    def test_empty_vs_empty(self, tmp_path):
        """Both current and previous are empty → no new, no resolved."""
        prev_path = _write_prev_report([], str(tmp_path))
        result = _compute_diff([], prev_path)

        assert result is not None
        assert result["summary"]["new_count"] == 0
        assert result["summary"]["resolved_count"] == 0
        assert result["summary"]["unchanged_count"] == 0

    def test_all_new(self, tmp_path):
        """Previous empty, current has findings → all new."""
        prev_path = _write_prev_report([], str(tmp_path))
        current = [
            _make_finding("Network Scanner", "Suspicious connection to 1.2.3.4"),
            _make_finding("Process Scanner", "Unsigned process running"),
        ]
        result = _compute_diff(current, prev_path)

        assert result is not None
        assert result["summary"]["new_count"] == 2
        assert result["summary"]["resolved_count"] == 0
        assert result["summary"]["unchanged_count"] == 0
        assert len(result["new"]) == 2

    def test_all_resolved(self, tmp_path):
        """Previous has findings, current empty → all resolved."""
        prev_findings = [
            {"module": "Network Scanner", "risk": "INFO", "title": "Open port 80"},
            {"module": "DNS Scanner", "risk": "MEDIUM", "title": "DGA domain detected"},
        ]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff([], prev_path)

        assert result is not None
        assert result["summary"]["new_count"] == 0
        assert result["summary"]["resolved_count"] == 2
        assert result["summary"]["unchanged_count"] == 0
        assert len(result["resolved"]) == 2

    def test_all_unchanged(self, tmp_path):
        """Same findings in both → all unchanged."""
        prev_findings = [
            {"module": "Port Scanner", "risk": "INFO", "title": "Port 443 open"},
        ]
        current = [_make_finding("Port Scanner", "Port 443 open")]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff(current, prev_path)

        assert result is not None
        assert result["summary"]["new_count"] == 0
        assert result["summary"]["resolved_count"] == 0
        assert result["summary"]["unchanged_count"] == 1

    def test_mixed_new_resolved_unchanged(self, tmp_path):
        """Mix of new, resolved, and unchanged findings."""
        prev_findings = [
            {"module": "Network Scanner", "risk": "HIGH", "title": "C2 beacon detected"},
            {"module": "Port Scanner", "risk": "INFO", "title": "Port 22 open"},
            {"module": "DNS Scanner", "risk": "MEDIUM", "title": "Suspicious domain query"},
        ]
        current = [
            _make_finding("Port Scanner", "Port 22 open"),            # unchanged
            _make_finding("File Scanner", "YARA match: Mimikatz"),    # new
            _make_finding("Process Scanner", "Unsigned binary", RiskLevel.HIGH),  # new
        ]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff(current, prev_path)

        assert result is not None
        assert result["summary"]["new_count"] == 2
        assert result["summary"]["resolved_count"] == 2  # C2 beacon + Suspicious domain
        assert result["summary"]["unchanged_count"] == 1  # Port 22 open


class TestComputeDiffIdentityKey:
    """Test that (module, title) is the comparison key, not description."""

    def test_same_title_different_description(self, tmp_path):
        """Same (module, title) with different description → unchanged."""
        prev_findings = [
            {"module": "Network Scanner", "risk": "INFO",
             "title": "Active connection", "description": "Old description"},
        ]
        current = [
            _make_finding("Network Scanner", "Active connection",
                          description="New description"),
        ]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff(current, prev_path)

        assert result["summary"]["unchanged_count"] == 1
        assert result["summary"]["new_count"] == 0

    def test_same_title_different_module(self, tmp_path):
        """Same title but different module → not matched (new + resolved)."""
        prev_findings = [
            {"module": "Network Scanner", "risk": "INFO", "title": "Suspicious activity"},
        ]
        current = [
            _make_finding("DNS Scanner", "Suspicious activity"),
        ]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff(current, prev_path)

        assert result["summary"]["new_count"] == 1
        assert result["summary"]["resolved_count"] == 1
        assert result["summary"]["unchanged_count"] == 0


class TestComputeDiffMetadata:
    """Test metadata fields in diff result."""

    def test_previous_report_path(self, tmp_path):
        """Diff result contains the previous report path."""
        prev_path = _write_prev_report([], str(tmp_path))
        result = _compute_diff([], prev_path)
        assert result["previous_report"] == prev_path

    def test_previous_scan_time(self, tmp_path):
        """Diff result contains the previous scan time."""
        prev_path = _write_prev_report(
            [], str(tmp_path), scan_time="2025-06-15T14:30:00"
        )
        result = _compute_diff([], prev_path)
        assert result["previous_scan_time"] == "2025-06-15T14:30:00"

    def test_previous_risk_score(self, tmp_path):
        """Diff result contains the previous risk score."""
        prev_path = _write_prev_report([], str(tmp_path), risk_score=65)
        result = _compute_diff([], prev_path)
        assert result["previous_risk_score"] == 65

    def test_default_risk_score_missing(self, tmp_path):
        """Missing risk_score in previous report → -1."""
        path = os.path.join(str(tmp_path), "no_score.json")
        with open(path, "w") as f:
            json.dump({"findings": []}, f)
        result = _compute_diff([], path)
        assert result["previous_risk_score"] == -1


class TestComputeDiffErrorHandling:
    """Test graceful error handling."""

    def test_file_not_found(self):
        """Non-existent path → None."""
        result = _compute_diff([], "/nonexistent/path/report.json")
        assert result is None

    def test_invalid_json(self, tmp_path):
        """Corrupt/invalid JSON → None."""
        bad_path = os.path.join(str(tmp_path), "bad.json")
        with open(bad_path, "w") as f:
            f.write("{{not valid json,,")
        result = _compute_diff([], bad_path)
        assert result is None

    def test_missing_findings_key(self, tmp_path):
        """JSON with no findings key → empty list, not error."""
        path = os.path.join(str(tmp_path), "no_findings.json")
        with open(path, "w") as f:
            json.dump({"scanner": "Corvus"}, f)
        result = _compute_diff([], path)
        # findings defaults to [] → no new, no resolved
        assert result is not None
        assert result["summary"]["new_count"] == 0
        assert result["summary"]["resolved_count"] == 0

    def test_findings_not_list(self, tmp_path):
        """JSON with findings as non-list → None."""
        path = os.path.join(str(tmp_path), "bad_findings.json")
        with open(path, "w") as f:
            json.dump({"findings": "not a list"}, f)
        result = _compute_diff([], path)
        assert result is None

    def test_empty_json_file(self, tmp_path):
        """Empty file → None (JSONDecodeError)."""
        path = os.path.join(str(tmp_path), "empty.json")
        with open(path, "w") as f:
            pass  # empty file
        result = _compute_diff([], path)
        assert result is None


class TestComputeDiffFindingLists:
    """Test that the actual finding lists are correctly populated."""

    def test_new_findings_are_finding_objects(self, tmp_path):
        """New findings in result should be Finding instances."""
        prev_path = _write_prev_report([], str(tmp_path))
        current = [_make_finding("Test Module", "Test Finding", RiskLevel.HIGH)]
        result = _compute_diff(current, prev_path)

        assert len(result["new"]) == 1
        assert isinstance(result["new"][0], Finding)
        assert result["new"][0].risk == RiskLevel.HIGH

    def test_resolved_findings_are_dicts(self, tmp_path):
        """Resolved findings should be raw dicts from the previous JSON."""
        prev_findings = [
            {"module": "Test Module", "risk": "CRITICAL", "title": "Old threat"},
        ]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff([], prev_path)

        assert len(result["resolved"]) == 1
        assert isinstance(result["resolved"][0], dict)
        assert result["resolved"][0]["title"] == "Old threat"

    def test_unchanged_findings_are_finding_objects(self, tmp_path):
        """Unchanged findings should be current Finding instances."""
        prev_findings = [
            {"module": "Port Scanner", "risk": "INFO", "title": "Port 80 open"},
        ]
        current = [_make_finding("Port Scanner", "Port 80 open")]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff(current, prev_path)

        assert len(result["unchanged"]) == 1
        assert isinstance(result["unchanged"][0], Finding)

    def test_large_diff(self, tmp_path):
        """Stress test with many findings."""
        prev_findings = [
            {"module": f"Mod{i}", "risk": "INFO", "title": f"Finding {i}"}
            for i in range(100)
        ]
        current = [
            _make_finding(f"Mod{i}", f"Finding {i}")
            for i in range(50, 150)  # 50 unchanged (50-99), 50 new (100-149)
        ]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff(current, prev_path)

        assert result["summary"]["new_count"] == 50       # 100-149
        assert result["summary"]["resolved_count"] == 50   # 0-49
        assert result["summary"]["unchanged_count"] == 50  # 50-99


class TestComputeDiffEdgeCases:
    """Edge cases and corner cases."""

    def test_duplicate_findings_in_current(self, tmp_path):
        """Duplicate (module, title) in current — both count as 'new' or 'unchanged'."""
        prev_findings = [
            {"module": "Net", "risk": "INFO", "title": "Connection A"},
        ]
        current = [
            _make_finding("Net", "Connection A"),
            _make_finding("Net", "Connection A"),  # duplicate
        ]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff(current, prev_path)

        # Both are in current and key exists in prev → both unchanged
        assert result["summary"]["unchanged_count"] == 2
        assert result["summary"]["new_count"] == 0

    def test_special_chars_in_title(self, tmp_path):
        """Titles with special characters match correctly."""
        title = 'File "C:\\Windows\\temp\\malware.exe" detected <script>'
        prev_findings = [
            {"module": "File Scanner", "risk": "HIGH", "title": title},
        ]
        current = [_make_finding("File Scanner", title, RiskLevel.HIGH)]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff(current, prev_path)

        assert result["summary"]["unchanged_count"] == 1
        assert result["summary"]["new_count"] == 0

    def test_unicode_in_title(self, tmp_path):
        """Unicode titles match correctly."""
        title = "Dosya algılandı: злоумышленник.exe"
        prev_findings = [
            {"module": "File Scanner", "risk": "HIGH", "title": title},
        ]
        current = [_make_finding("File Scanner", title, RiskLevel.HIGH)]
        prev_path = _write_prev_report(prev_findings, str(tmp_path))
        result = _compute_diff(current, prev_path)

        assert result["summary"]["unchanged_count"] == 1

    def test_identical_scans(self, tmp_path):
        """Exact same findings in both → all unchanged, zero new/resolved."""
        findings_data = [
            {"module": "Net", "risk": "INFO", "title": "A"},
            {"module": "DNS", "risk": "MEDIUM", "title": "B"},
            {"module": "Port", "risk": "HIGH", "title": "C"},
        ]
        current = [
            _make_finding("Net", "A"),
            _make_finding("DNS", "B", RiskLevel.MEDIUM),
            _make_finding("Port", "C", RiskLevel.HIGH),
        ]
        prev_path = _write_prev_report(findings_data, str(tmp_path))
        result = _compute_diff(current, prev_path)

        assert result["summary"]["new_count"] == 0
        assert result["summary"]["resolved_count"] == 0
        assert result["summary"]["unchanged_count"] == 3
