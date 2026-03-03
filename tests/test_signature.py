"""Tests for ctypes WinVerifyTrust signature verification, LRU cache,
and trusted signer matching."""

import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from scanner_core.utils import (
    check_file_signature,
    is_trusted_signer,
    _LRUSignatureCache,
)


# ---------------------------------------------------------------------------
# LRU Cache Unit Tests (platform-independent)
# ---------------------------------------------------------------------------

class TestLRUSignatureCache:
    """Unit tests for the OrderedDict-based LRU cache."""

    def test_cache_hit(self):
        cache = _LRUSignatureCache(maxsize=10)
        cache.put("a", {"signed": True, "signer": "Test", "trusted": True})
        assert cache.get("a") == {"signed": True, "signer": "Test", "trusted": True}

    def test_cache_miss(self):
        cache = _LRUSignatureCache(maxsize=10)
        assert cache.get("nonexistent") is None

    def test_eviction_at_capacity(self):
        cache = _LRUSignatureCache(maxsize=3)
        cache.put("a", {"v": 1})
        cache.put("b", {"v": 2})
        cache.put("c", {"v": 3})
        cache.put("d", {"v": 4})  # evicts "a" (oldest)
        assert cache.get("a") is None
        assert cache.get("b") == {"v": 2}
        assert cache.get("d") == {"v": 4}

    def test_access_refreshes_lru_order(self):
        cache = _LRUSignatureCache(maxsize=3)
        cache.put("a", {"v": 1})
        cache.put("b", {"v": 2})
        cache.put("c", {"v": 3})
        cache.get("a")  # refresh "a" — moves to end
        cache.put("d", {"v": 4})  # evicts "b" (oldest untouched)
        assert cache.get("a") == {"v": 1}
        assert cache.get("b") is None

    def test_update_existing_key(self):
        cache = _LRUSignatureCache(maxsize=10)
        cache.put("a", {"v": 1})
        cache.put("a", {"v": 2})
        assert cache.get("a") == {"v": 2}

    def test_update_does_not_grow(self):
        cache = _LRUSignatureCache(maxsize=3)
        cache.put("a", {"v": 1})
        cache.put("b", {"v": 2})
        cache.put("c", {"v": 3})
        cache.put("a", {"v": 99})  # update, not insert
        cache.put("d", {"v": 4})  # evicts "b", not "a"
        assert cache.get("a") == {"v": 99}
        assert cache.get("b") is None
        assert cache.get("c") is not None

    def test_maxsize_one(self):
        cache = _LRUSignatureCache(maxsize=1)
        cache.put("a", {"v": 1})
        cache.put("b", {"v": 2})
        assert cache.get("a") is None
        assert cache.get("b") == {"v": 2}


# ---------------------------------------------------------------------------
# Signature Verification Integration Tests (Windows-only)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
@pytest.mark.skipif(
    not os.path.isfile(r"C:\Windows\System32\notepad.exe"),
    reason="notepad.exe not found",
)
class TestCatalogSigned:
    """Integration tests for catalog-signed Windows binaries."""

    def test_notepad_is_signed(self):
        result = check_file_signature(r"C:\Windows\System32\notepad.exe")
        assert result["signed"] is True
        assert "microsoft" in result["signer"].lower()
        assert result["trusted"] is True

    def test_svchost_is_signed(self):
        result = check_file_signature(r"C:\Windows\System32\svchost.exe")
        assert result["signed"] is True
        assert result["trusted"] is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
@pytest.mark.skipif(
    not os.path.isfile(r"C:\Windows\explorer.exe"),
    reason="explorer.exe not found",
)
class TestEmbeddedSigned:
    """Integration tests for embedded Authenticode signed binaries."""

    def test_explorer_is_signed(self):
        result = check_file_signature(r"C:\Windows\explorer.exe")
        assert result["signed"] is True
        assert result["trusted"] is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
class TestUnsigned:
    """Test behavior with unsigned/nonexistent files."""

    def test_nonexistent_file(self):
        result = check_file_signature(r"C:\nonexistent_path\fake.exe")
        assert result["signed"] is False
        assert result["trusted"] is False
        assert result["signer"] == "Unknown"

    def test_empty_path(self):
        result = check_file_signature("")
        assert result["signed"] is False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only")
class TestReturnTypeContract:
    """Verify the return type contract is preserved for all callers."""

    def test_return_dict_keys(self):
        result = check_file_signature(r"C:\Windows\System32\notepad.exe")
        assert set(result.keys()) == {"signed", "signer", "trusted"}
        assert isinstance(result["signed"], bool)
        assert isinstance(result["signer"], str)
        assert isinstance(result["trusted"], bool)

    def test_cache_returns_same_contract(self):
        """Second call (cached) should return identical structure."""
        path = r"C:\Windows\System32\notepad.exe"
        r1 = check_file_signature(path)
        r2 = check_file_signature(path)
        assert r1 == r2
        assert set(r2.keys()) == {"signed", "signer", "trusted"}


# ---------------------------------------------------------------------------
# Trusted Signer Matching Tests (platform-independent)
# ---------------------------------------------------------------------------

class TestTrustedSignerExactMatch:
    """Verify exact match works for known trusted signers."""

    def test_exact_microsoft_corporation(self):
        assert is_trusted_signer("Microsoft Corporation") is True

    def test_exact_google_llc(self):
        assert is_trusted_signer("Google LLC") is True

    def test_exact_case_insensitive(self):
        assert is_trusted_signer("MICROSOFT CORPORATION") is True
        assert is_trusted_signer("google llc") is True

    def test_exact_with_quotes(self):
        assert is_trusted_signer('"Microsoft Corporation"') is True


class TestTrustedSignerPrefixMatch:
    """Verify prefix match catches extended signer names."""

    def test_microsoft_windows_publisher(self):
        assert is_trusted_signer("Microsoft Windows Publisher") is True

    def test_google_llc_extended(self):
        assert is_trusted_signer("Google LLC (US)") is True

    def test_nvidia_corporation_extended(self):
        assert is_trusted_signer("NVIDIA Corporation PE Sign") is True


class TestTrustedSignerSpoofPrevention:
    """Verify substring spoofing is blocked (Sprint 1.3 core requirement)."""

    def test_notmicrosoft_blocked(self):
        """'notmicrosoft corp' must NOT match 'microsoft'."""
        assert is_trusted_signer("notmicrosoft corp") is False

    def test_fakegoogle_blocked(self):
        assert is_trusted_signer("fakegoogle llc") is False

    def test_prefix_without_space_blocked(self):
        """'microsoftevil' must NOT match 'microsoft'."""
        assert is_trusted_signer("microsoftevil") is False

    def test_embedded_substring_blocked(self):
        """'totally not microsoft at all' must NOT match."""
        assert is_trusted_signer("totally not microsoft at all") is False

    def test_suffix_match_blocked(self):
        """'evil microsoft' must NOT match (not a prefix of a trusted entry)."""
        assert is_trusted_signer("evil microsoft") is False


class TestTrustedSignerEdgeCases:
    """Edge cases for is_trusted_signer."""

    def test_empty_string(self):
        assert is_trusted_signer("") is False

    def test_none_value(self):
        assert is_trusted_signer(None) is False

    def test_unknown(self):
        assert is_trusted_signer("Unknown") is False

    def test_random_signer(self):
        assert is_trusted_signer("Some Random Corp LLC") is False
