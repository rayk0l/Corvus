"""Tests for online enrichment module — all API calls mocked."""

import sys
import os
import json
import time
import pytest
from unittest.mock import patch, MagicMock
from urllib.error import HTTPError

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner_core.models import Finding, RiskLevel
from scanner_core.online_enrichment import (
    configure,
    enrich_findings,
    _vt_lookup,
    _abuseipdb_lookup,
    _maybe_upgrade_risk_vt,
    _maybe_upgrade_risk_abuseipdb,
    _apply_upgrade,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_module_state():
    """Reset global state before each test."""
    configure({"vt_api_key": "", "abuseipdb_api_key": ""})
    yield
    configure({"vt_api_key": "", "abuseipdb_api_key": ""})


@pytest.fixture
def hash_finding():
    return Finding(
        module="File Scanner",
        risk=RiskLevel.MEDIUM,
        title="Suspicious file detected",
        description="test",
        details={"sha256": "a" * 64, "path": "C:\\tmp\\bad.exe"},
    )


@pytest.fixture
def ip_finding():
    return Finding(
        module="Network Scanner",
        risk=RiskLevel.MEDIUM,
        title="Suspicious connection",
        description="test",
        details={"remote_ip": "185.220.101.1", "remote_port": 443},
    )


def _mock_vt_response(malicious=5, suspicious=0, undetected=60, harmless=6):
    """Create mock VirusTotal API response."""
    data = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": malicious,
                    "suspicious": suspicious,
                    "undetected": undetected,
                    "harmless": harmless,
                }
            }
        }
    }
    resp = MagicMock()
    resp.read.return_value = json.dumps(data).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


def _mock_abuseipdb_response(score=85, reports=120, country="RU"):
    """Create mock AbuseIPDB API response."""
    data = {
        "data": {
            "abuseConfidenceScore": score,
            "totalReports": reports,
            "countryCode": country,
        }
    }
    resp = MagicMock()
    resp.read.return_value = json.dumps(data).encode()
    resp.__enter__ = lambda s: s
    resp.__exit__ = MagicMock(return_value=False)
    return resp


# ---------------------------------------------------------------------------
# Configure Tests (4)
# ---------------------------------------------------------------------------

class TestConfigure:
    def test_both_keys_enables(self):
        configure({"vt_api_key": "VT_KEY", "abuseipdb_api_key": "AIPDB_KEY"})
        result = enrich_findings([])
        assert result is not None  # enabled, returns empty summary

    def test_no_keys_disables(self):
        configure({})
        result = enrich_findings([])
        assert result is None  # disabled

    def test_vt_only_enables(self):
        configure({"vt_api_key": "VT_KEY"})
        result = enrich_findings([])
        assert result is not None

    def test_whitespace_key_ignored(self):
        configure({"vt_api_key": "   ", "abuseipdb_api_key": ""})
        result = enrich_findings([])
        assert result is None


# ---------------------------------------------------------------------------
# VT Lookup Tests (6)
# ---------------------------------------------------------------------------

class TestVTLookup:
    @patch("scanner_core.online_enrichment.urlopen")
    def test_success(self, mock_urlopen):
        configure({"vt_api_key": "KEY"})
        mock_urlopen.return_value = _mock_vt_response(malicious=45, undetected=20, harmless=6)
        result = _vt_lookup("a" * 64)
        assert result is not None
        assert result["vt_detection"] == 45
        assert result["vt_score"] == "45/71"
        assert "virustotal.com" in result["vt_link"]

    @patch("scanner_core.online_enrichment.urlopen")
    def test_404_not_found(self, mock_urlopen):
        configure({"vt_api_key": "KEY"})
        mock_urlopen.side_effect = HTTPError(None, 404, "Not Found", {}, None)
        result = _vt_lookup("b" * 64)
        assert result is not None
        assert result["vt_score"] == "not found"

    @patch("scanner_core.online_enrichment.urlopen")
    def test_timeout(self, mock_urlopen):
        configure({"vt_api_key": "KEY"})
        mock_urlopen.side_effect = TimeoutError("timeout")
        result = _vt_lookup("c" * 64)
        assert result is None

    @patch("scanner_core.online_enrichment.urlopen")
    def test_bad_json(self, mock_urlopen):
        configure({"vt_api_key": "KEY"})
        resp = MagicMock()
        resp.read.return_value = b"not json"
        resp.__enter__ = lambda s: s
        resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp
        result = _vt_lookup("d" * 64)
        assert result is None

    @patch("scanner_core.online_enrichment.urlopen")
    def test_cache_hit(self, mock_urlopen):
        configure({"vt_api_key": "KEY"})
        mock_urlopen.return_value = _mock_vt_response(10, 0, 55, 6)
        _vt_lookup("e" * 64)
        # Second call should use cache — need new mock to avoid exhaustion
        mock_urlopen.return_value = _mock_vt_response(99, 0, 0, 0)
        result = _vt_lookup("e" * 64)
        assert result["vt_detection"] == 10  # cached result, not 99
        assert mock_urlopen.call_count == 1

    def test_no_key_returns_none(self):
        configure({})
        result = _vt_lookup("f" * 64)
        assert result is None


# ---------------------------------------------------------------------------
# AbuseIPDB Lookup Tests (5)
# ---------------------------------------------------------------------------

class TestAbuseIPDBLookup:
    @patch("scanner_core.online_enrichment.urlopen")
    def test_success(self, mock_urlopen):
        configure({"abuseipdb_api_key": "KEY"})
        mock_urlopen.return_value = _mock_abuseipdb_response(score=85)
        result = _abuseipdb_lookup("185.220.101.1")
        assert result is not None
        assert result["abuseipdb_score"] == 85
        assert result["abuseipdb_country"] == "RU"
        assert "abuseipdb.com" in result["abuseipdb_link"]

    @patch("scanner_core.online_enrichment.urlopen")
    def test_server_error(self, mock_urlopen):
        configure({"abuseipdb_api_key": "KEY"})
        mock_urlopen.side_effect = HTTPError(None, 500, "Server Error", {}, None)
        result = _abuseipdb_lookup("1.2.3.4")
        assert result is None

    @patch("scanner_core.online_enrichment.urlopen")
    def test_cache_hit(self, mock_urlopen):
        configure({"abuseipdb_api_key": "KEY"})
        mock_urlopen.return_value = _mock_abuseipdb_response(score=50)
        _abuseipdb_lookup("5.6.7.8")
        mock_urlopen.return_value = _mock_abuseipdb_response(score=99)
        result = _abuseipdb_lookup("5.6.7.8")
        assert result["abuseipdb_score"] == 50  # cached
        assert mock_urlopen.call_count == 1

    @patch("scanner_core.online_enrichment.urlopen")
    def test_429_stops_queries(self, mock_urlopen):
        configure({"abuseipdb_api_key": "KEY"})
        mock_urlopen.side_effect = HTTPError(None, 429, "Rate Limit", {}, None)
        _abuseipdb_lookup("9.10.11.12")
        # After 429, daily limit is set — next call should return None without HTTP
        result = _abuseipdb_lookup("13.14.15.16")
        assert result is None

    def test_no_key_returns_none(self):
        configure({})
        result = _abuseipdb_lookup("1.2.3.4")
        assert result is None


# ---------------------------------------------------------------------------
# Risk Upgrade Tests (6)
# ---------------------------------------------------------------------------

class TestRiskUpgrade:
    def test_vt_above_50_pct_upgrades_to_critical(self):
        f = Finding(module="T", risk=RiskLevel.MEDIUM, title="t", description="d")
        upgraded = _maybe_upgrade_risk_vt(f, {"vt_detection": 40, "vt_total": 71})
        assert upgraded is True
        assert f.risk == RiskLevel.CRITICAL

    def test_vt_above_20_pct_upgrades_to_high(self):
        f = Finding(module="T", risk=RiskLevel.MEDIUM, title="t", description="d")
        upgraded = _maybe_upgrade_risk_vt(f, {"vt_detection": 15, "vt_total": 71})
        assert upgraded is True
        assert f.risk == RiskLevel.HIGH

    def test_vt_below_20_pct_no_upgrade(self):
        f = Finding(module="T", risk=RiskLevel.MEDIUM, title="t", description="d")
        upgraded = _maybe_upgrade_risk_vt(f, {"vt_detection": 5, "vt_total": 71})
        assert upgraded is False
        assert f.risk == RiskLevel.MEDIUM

    def test_abuseipdb_above_80_upgrades_to_critical(self):
        f = Finding(module="T", risk=RiskLevel.MEDIUM, title="t", description="d")
        upgraded = _maybe_upgrade_risk_abuseipdb(f, {"abuseipdb_score": 95})
        assert upgraded is True
        assert f.risk == RiskLevel.CRITICAL

    def test_abuseipdb_above_50_upgrades_to_high(self):
        f = Finding(module="T", risk=RiskLevel.INFO, title="t", description="d")
        upgraded = _maybe_upgrade_risk_abuseipdb(f, {"abuseipdb_score": 60})
        assert upgraded is True
        assert f.risk == RiskLevel.HIGH

    def test_never_downgrades(self):
        f = Finding(module="T", risk=RiskLevel.CRITICAL, title="t", description="d")
        upgraded = _maybe_upgrade_risk_vt(f, {"vt_detection": 15, "vt_total": 71})
        assert upgraded is False
        assert f.risk == RiskLevel.CRITICAL

    def test_upgrade_adds_metadata(self):
        f = Finding(module="T", risk=RiskLevel.INFO, title="t", description="d")
        _maybe_upgrade_risk_vt(f, {"vt_detection": 50, "vt_total": 71})
        assert f.details["risk_upgraded_by"] == "virustotal"
        assert f.details["original_risk"] == "INFO"

    def test_vt_zero_total_no_upgrade(self):
        f = Finding(module="T", risk=RiskLevel.INFO, title="t", description="d")
        upgraded = _maybe_upgrade_risk_vt(f, {"vt_detection": 0, "vt_total": 0})
        assert upgraded is False

    def test_abuseipdb_below_50_no_upgrade(self):
        f = Finding(module="T", risk=RiskLevel.INFO, title="t", description="d")
        upgraded = _maybe_upgrade_risk_abuseipdb(f, {"abuseipdb_score": 30})
        assert upgraded is False
        assert f.risk == RiskLevel.INFO


# ---------------------------------------------------------------------------
# Integration Tests (5)
# ---------------------------------------------------------------------------

class TestEnrichmentIntegration:
    @patch("scanner_core.online_enrichment.urlopen")
    def test_full_enrichment(self, mock_urlopen, hash_finding, ip_finding):
        configure({"vt_api_key": "VT", "abuseipdb_api_key": "AIPDB"})

        def side_effect(req, **kwargs):
            url = req.full_url
            if "virustotal" in url:
                return _mock_vt_response(45, 0, 20, 6)
            elif "abuseipdb" in url:
                return _mock_abuseipdb_response(85)
            raise ValueError(f"Unexpected URL: {url}")

        mock_urlopen.side_effect = side_effect
        summary = enrich_findings([hash_finding, ip_finding])

        assert summary is not None
        assert summary["hashes_queried"] == 1
        assert summary["ips_queried"] == 1
        assert summary["vt_hits"] == 1
        assert summary["abuseipdb_hits"] == 1
        # Hash finding should be enriched
        assert "vt_score" in hash_finding.details
        assert hash_finding.details["vt_score"] == "45/71"
        # IP finding should be enriched
        assert "abuseipdb_score" in ip_finding.details
        assert ip_finding.details["abuseipdb_score"] == 85

    def test_no_enrichable_findings(self):
        configure({"vt_api_key": "KEY"})
        f = Finding(
            module="T", risk=RiskLevel.INFO, title="t", description="d",
            details={"path": "/tmp/file"},  # no sha256 or remote_ip
        )
        summary = enrich_findings([f])
        assert summary is not None
        assert summary["hashes_queried"] == 0
        assert summary["ips_queried"] == 0

    def test_disabled_returns_none(self):
        configure({})
        f = Finding(
            module="T", risk=RiskLevel.INFO, title="t", description="d",
            details={"sha256": "a" * 64},
        )
        result = enrich_findings([f])
        assert result is None

    def test_private_ip_skipped(self):
        """Private IPs should not be queried."""
        configure({"abuseipdb_api_key": "KEY"})
        f = Finding(
            module="T", risk=RiskLevel.INFO, title="t", description="d",
            details={"remote_ip": "192.168.1.1"},
        )
        summary = enrich_findings([f])
        assert summary["ips_queried"] == 0

    def test_invalid_hash_length_skipped(self):
        """Non-64-char hashes should not be queried."""
        configure({"vt_api_key": "KEY"})
        f = Finding(
            module="T", risk=RiskLevel.INFO, title="t", description="d",
            details={"sha256": "tooshort"},
        )
        summary = enrich_findings([f])
        assert summary["hashes_queried"] == 0

    @patch("scanner_core.online_enrichment.urlopen")
    def test_risk_upgrade_reflected_in_summary(self, mock_urlopen, hash_finding):
        """VT detection >50% should upgrade risk and count in summary."""
        configure({"vt_api_key": "VT"})
        # 45/71 = 63% > 50% → CRITICAL
        mock_urlopen.return_value = _mock_vt_response(malicious=45, undetected=20, harmless=6)
        summary = enrich_findings([hash_finding])
        assert summary["risk_upgrades"] == 1
        assert hash_finding.risk == RiskLevel.CRITICAL
        assert hash_finding.details.get("risk_upgraded_by") == "virustotal"
        assert hash_finding.details.get("original_risk") == "MEDIUM"

    @patch("scanner_core.online_enrichment.urlopen")
    def test_duplicate_hashes_queried_once(self, mock_urlopen):
        """Multiple findings with same hash should result in only 1 API call."""
        configure({"vt_api_key": "VT"})
        mock_urlopen.return_value = _mock_vt_response(5, 0, 60, 6)

        h = "a" * 64
        f1 = Finding(module="T", risk=RiskLevel.MEDIUM, title="t1", description="d",
                     details={"sha256": h})
        f2 = Finding(module="T", risk=RiskLevel.INFO, title="t2", description="d",
                     details={"sha256": h})

        summary = enrich_findings([f1, f2])
        assert summary["hashes_queried"] == 1
        assert mock_urlopen.call_count == 1
        # Both findings should be enriched
        assert "vt_score" in f1.details
        assert "vt_score" in f2.details
