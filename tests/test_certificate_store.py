"""
Tests for certificate store scanner — Sprint 4.4.

Tests cover:
  - _is_trusted_issuer() matching logic (exact, prefix, contains)
  - TRUSTED_ROOT_ISSUERS data structure integrity
  - WEAK_ALGORITHMS data structure integrity
  - _filetime_to_datetime() conversion
  - _enumerate_store_certs() returns list of dicts
  - scan() returns List[Finding] with correct module name
  - Finding contract validation (module, risk, mitre_id)
"""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner_core.models import Finding, RiskLevel
from scanners.certificate_store_scanner import (
    _is_trusted_issuer,
    _filetime_to_datetime,
    TRUSTED_ROOT_ISSUERS,
    WEAK_ALGORITHMS,
    FILETIME,
)


# ---------------------------------------------------------------------------
# Trusted Issuer Matching Tests
# ---------------------------------------------------------------------------

class TestTrustedIssuerMatching:
    """Test _is_trusted_issuer() exact + prefix + contains matching."""

    def test_exact_match_microsoft(self):
        assert _is_trusted_issuer("Microsoft Corporation") is True

    def test_exact_match_digicert(self):
        assert _is_trusted_issuer("DigiCert Global Root CA") is True

    def test_exact_match_globalsign(self):
        assert _is_trusted_issuer("GlobalSign Root CA") is True

    def test_exact_match_case_insensitive(self):
        assert _is_trusted_issuer("MICROSOFT CORPORATION") is True
        assert _is_trusted_issuer("digicert global root ca") is True

    def test_prefix_match_microsoft_extended(self):
        """Microsoft with extra text after space should match."""
        assert _is_trusted_issuer("Microsoft Root Certificate Authority 2011") is True

    def test_contains_match_in_cn(self):
        """Issuer CN that contains a known CA name should match."""
        assert _is_trusted_issuer("DigiCert Inc, OU=DigiCert Global Root G2") is True

    def test_unknown_issuer_rejected(self):
        assert _is_trusted_issuer("Evil Corp Root CA") is False

    def test_similar_name_rejected(self):
        """Names that look similar but aren't in the list."""
        assert _is_trusted_issuer("Micr0soft Corporation") is False

    def test_empty_string_rejected(self):
        assert _is_trusted_issuer("") is False

    def test_none_rejected(self):
        assert _is_trusted_issuer(None) is False

    def test_whitespace_only_rejected(self):
        assert _is_trusted_issuer("   ") is False

    def test_lets_encrypt(self):
        assert _is_trusted_issuer("ISRG Root X1") is True

    def test_amazon_root(self):
        assert _is_trusted_issuer("Amazon Root CA 1") is True

    def test_google_trust(self):
        assert _is_trusted_issuer("Google Trust Services LLC") is True

    def test_comodo_rsa(self):
        assert _is_trusted_issuer("COMODO RSA Certification Authority") is True

    def test_sectigo(self):
        assert _is_trusted_issuer("Sectigo") is True


# ---------------------------------------------------------------------------
# Data Structure Tests
# ---------------------------------------------------------------------------

class TestDataStructures:
    def test_trusted_issuers_are_lowercase(self):
        """All entries in TRUSTED_ROOT_ISSUERS must be lowercase."""
        for issuer in TRUSTED_ROOT_ISSUERS:
            assert issuer == issuer.lower(), f"Not lowercase: '{issuer}'"

    def test_trusted_issuers_has_major_cas(self):
        """Must include the major CAs."""
        major = ["microsoft", "digicert", "globalsign", "comodo",
                 "sectigo", "amazon", "verisign"]
        for ca in major:
            assert any(ca in issuer for issuer in TRUSTED_ROOT_ISSUERS), (
                f"Missing major CA: {ca}"
            )

    def test_weak_algorithms_have_correct_structure(self):
        """Each entry: OID → (friendly_name, RiskLevel)."""
        for oid, (name, risk) in WEAK_ALGORITHMS.items():
            assert isinstance(oid, str)
            assert isinstance(name, str)
            assert isinstance(risk, RiskLevel)

    def test_md5_is_high_risk(self):
        """MD5-RSA must be HIGH risk."""
        md5_oid = "1.2.840.113549.1.1.4"
        assert md5_oid in WEAK_ALGORITHMS
        assert WEAK_ALGORITHMS[md5_oid][1] == RiskLevel.HIGH

    def test_sha1_is_medium_risk(self):
        """SHA1-RSA must be MEDIUM risk."""
        sha1_oid = "1.2.840.113549.1.1.5"
        assert sha1_oid in WEAK_ALGORITHMS
        assert WEAK_ALGORITHMS[sha1_oid][1] == RiskLevel.MEDIUM


# ---------------------------------------------------------------------------
# FILETIME Conversion Tests
# ---------------------------------------------------------------------------

class TestFiletimeConversion:
    def test_zero_returns_none(self):
        ft = FILETIME(0, 0)
        assert _filetime_to_datetime(ft) is None

    def test_known_timestamp(self):
        """2023-01-01 00:00:00 UTC = FILETIME 133170048000000000."""
        val = 133170048000000000
        low = val & 0xFFFFFFFF
        high = val >> 32
        ft = FILETIME(low, high)
        dt = _filetime_to_datetime(ft)
        assert dt is not None
        assert dt.year == 2023
        assert dt.month == 1
        assert dt.day == 1

    def test_return_type_is_datetime_or_none(self):
        ft = FILETIME(0, 0)
        result = _filetime_to_datetime(ft)
        assert result is None or hasattr(result, "year")


# ---------------------------------------------------------------------------
# Integration Tests (Windows-only)
# ---------------------------------------------------------------------------

pytestmark_win = pytest.mark.skipif(
    sys.platform != "win32",
    reason="Certificate store access requires Windows",
)


@pytestmark_win
class TestEnumerateStoreCerts:
    def test_root_store_returns_list(self):
        from scanners.certificate_store_scanner import _enumerate_store_certs
        certs = _enumerate_store_certs("Root")
        assert isinstance(certs, list)

    def test_root_store_has_certs(self):
        """Windows Root store should have at least some certificates."""
        from scanners.certificate_store_scanner import _enumerate_store_certs
        certs = _enumerate_store_certs("Root")
        assert len(certs) > 0, "Root store should have certificates"

    def test_cert_dict_has_required_keys(self):
        from scanners.certificate_store_scanner import _enumerate_store_certs
        certs = _enumerate_store_certs("Root")
        if certs:
            cert = certs[0]
            assert "subject" in cert
            assert "issuer" in cert
            assert "not_before" in cert
            assert "not_after" in cert
            assert "sig_algorithm_oid" in cert
            assert "is_self_signed" in cert
            assert "store" in cert

    def test_nonexistent_store_returns_empty(self):
        from scanners.certificate_store_scanner import _enumerate_store_certs
        certs = _enumerate_store_certs("NonExistentStore12345")
        assert certs == []


@pytestmark_win
class TestScanIntegration:
    def test_scan_returns_list(self):
        from scanners.certificate_store_scanner import scan
        result = scan()
        assert isinstance(result, list)

    def test_all_findings_are_finding_instances(self):
        from scanners.certificate_store_scanner import scan
        result = scan()
        for f in result:
            assert isinstance(f, Finding)

    def test_all_findings_have_correct_module(self):
        from scanners.certificate_store_scanner import scan
        result = scan()
        for f in result:
            assert f.module == "Certificate Store Scanner"

    def test_all_findings_have_mitre_id(self):
        from scanners.certificate_store_scanner import scan
        result = scan()
        for f in result:
            assert f.mitre_id == "T1553.004"

    def test_all_findings_have_store_in_details(self):
        from scanners.certificate_store_scanner import scan
        result = scan()
        for f in result:
            # All findings should mention the store in details or description
            has_store = "store" in f.details or "Root" in f.description
            assert has_store, f"Missing store info: {f.title}"


@pytestmark_win
class TestRegistryCompletion:
    """Verify the module is properly registered."""

    def test_in_scanner_registry(self):
        from scanners import SCANNER_REGISTRY
        keys = {config_key for _, _, config_key in SCANNER_REGISTRY}
        assert "certificate_store_scanner" in keys

    def test_registry_count_is_24(self):
        from scanners import SCANNER_REGISTRY
        assert len(SCANNER_REGISTRY) == 24

    def test_not_in_heavy_modules(self):
        from scanners import HEAVY_MODULES
        assert "certificate_store_scanner" not in HEAVY_MODULES
