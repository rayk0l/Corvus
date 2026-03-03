"""Tests for YARA rule download, extraction, validation and FP management.

Covers:
  - ZIP extraction with prefix/exclude filtering
  - disabled_rules.txt parsing
  - Per-file YARA compilation validation
  - Namespace generation (custom vs community)
  - File scanner integration (_load_yara_rules resilience)
"""

import io
import json
import os
import zipfile

import pytest

# Conditional yara import
try:
    import yara

    HAS_YARA = True
except ImportError:
    HAS_YARA = False

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_YARA = 'rule test_rule { strings: $a = "test" condition: $a }'
VALID_YARA_B = 'rule test_rule_b { strings: $b = "hello" condition: $b }'
BROKEN_YARA = 'rule broken { strings: $a = "test" condition: INVALID_FUNC }'


def _create_test_zip(files: dict) -> bytes:
    """Create an in-memory ZIP with *files* = {path: content_str}."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for path, content in files.items():
            zf.writestr(path, content)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# ZIP Extraction Tests (4)
# ---------------------------------------------------------------------------

class TestZipExtraction:
    """_extract_yara_from_zip applies prefix/exclude filters correctly."""

    def test_include_prefix_filter(self, tmp_path):
        """Only apt_* and crime_* files are extracted."""
        from ioc_updater import YARA_FEEDS, _extract_yara_from_zip

        feed = YARA_FEEDS[0].copy()
        zip_bytes = _create_test_zip({
            "signature-base-master/yara/apt_test.yar": VALID_YARA,
            "signature-base-master/yara/crime_test.yar": VALID_YARA_B,
            "signature-base-master/yara/gen_test.yar": VALID_YARA,
        })
        _, count = _extract_yara_from_zip(zip_bytes, feed, str(tmp_path))
        assert count == 2  # only apt_ and crime_

    def test_exclude_specific_files(self, tmp_path):
        """Files in exclude_files set are skipped."""
        from ioc_updater import YARA_FEEDS, _extract_yara_from_zip

        feed = YARA_FEEDS[0].copy()
        zip_bytes = _create_test_zip({
            "signature-base-master/yara/apt_good.yar": VALID_YARA,
            "signature-base-master/yara/generic_anomalies.yar": VALID_YARA,
        })
        _, count = _extract_yara_from_zip(zip_bytes, feed, str(tmp_path))
        assert count == 1

    def test_exclude_prefix(self, tmp_path):
        """Files starting with thor- or thor_ are excluded."""
        from ioc_updater import YARA_FEEDS, _extract_yara_from_zip

        feed = YARA_FEEDS[0].copy()
        # thor_bad has apt_ prefix BUT also has thor_ prefix in exclude list?
        # No — thor_ is in exclude_prefixes, but the file must first pass
        # include_prefixes check.  Let's test directly.
        zip_bytes = _create_test_zip({
            "signature-base-master/yara/apt_good.yar": VALID_YARA,
            "signature-base-master/yara/thor_bad.yar": VALID_YARA,
            "signature-base-master/yara/thor-webshells.yar": VALID_YARA,
        })
        _, count = _extract_yara_from_zip(zip_bytes, feed, str(tmp_path))
        # thor_bad and thor-webshells don't start with apt_/crime_ → filtered
        # by include_prefixes, not exclude_prefixes.  But exclude also catches them.
        assert count == 1

    def test_idempotent_reextract(self, tmp_path):
        """Re-extracting wipes old files and recreates."""
        from ioc_updater import YARA_FEEDS, _extract_yara_from_zip

        feed = YARA_FEEDS[0].copy()
        zip_bytes = _create_test_zip({
            "signature-base-master/yara/apt_a.yar": VALID_YARA,
        })
        _extract_yara_from_zip(zip_bytes, feed, str(tmp_path))
        prev, new = _extract_yara_from_zip(zip_bytes, feed, str(tmp_path))
        assert prev == 1
        assert new == 1


# ---------------------------------------------------------------------------
# Disabled Rules Tests (3)
# ---------------------------------------------------------------------------

class TestDisabledRules:
    """disabled_rules.txt parsing edge cases."""

    def test_parse_entries(self, tmp_path):
        path = tmp_path / "disabled_rules.txt"
        path.write_text("# comment\napt_bad.yar\n\ncrime_old.yar\n")
        rules = set()
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    rules.add(line)
        assert rules == {"apt_bad.yar", "crime_old.yar"}

    def test_empty_file(self, tmp_path):
        path = tmp_path / "disabled_rules.txt"
        path.write_text("# only comments\n# nothing here\n")
        rules = set()
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    rules.add(line)
        assert len(rules) == 0

    def test_missing_file_no_crash(self, tmp_path):
        """Missing file should not crash — just yield empty set."""
        path = tmp_path / "disabled_rules.txt"
        assert not path.exists()
        disabled = set()
        # Mimics the pattern in _load_yara_rules
        if os.path.isfile(str(path)):
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        disabled.add(line)
        assert len(disabled) == 0


# ---------------------------------------------------------------------------
# YARA Validation Tests (3)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
class TestYaraValidation:
    """_validate_yara_rules quarantines broken rules."""

    def test_valid_rule_passes(self, tmp_path):
        from ioc_updater import _validate_yara_rules

        rules_dir = tmp_path / "community" / "neo23x0"
        rules_dir.mkdir(parents=True)
        (rules_dir / "apt_test.yar").write_text(VALID_YARA)
        valid, broken = _validate_yara_rules(str(tmp_path), "community/neo23x0")
        assert valid == 1
        assert broken == 0

    def test_broken_rule_quarantined(self, tmp_path):
        from ioc_updater import _validate_yara_rules

        rules_dir = tmp_path / "community" / "neo23x0"
        rules_dir.mkdir(parents=True)
        (rules_dir / "apt_broken.yar").write_text(BROKEN_YARA)
        valid, broken = _validate_yara_rules(str(tmp_path), "community/neo23x0")
        assert valid == 0
        assert broken == 1
        assert (rules_dir / "_broken" / "apt_broken.yar").exists()

    def test_mixed_valid_and_broken(self, tmp_path):
        from ioc_updater import _validate_yara_rules

        rules_dir = tmp_path / "community" / "neo23x0"
        rules_dir.mkdir(parents=True)
        (rules_dir / "apt_good.yar").write_text(VALID_YARA)
        (rules_dir / "crime_bad.yar").write_text(BROKEN_YARA)
        valid, broken = _validate_yara_rules(str(tmp_path), "community/neo23x0")
        assert valid == 1
        assert broken == 1


# ---------------------------------------------------------------------------
# Namespace Tests (3)
# ---------------------------------------------------------------------------

class TestNamespaces:
    """Namespace generation prevents rule-name collisions."""

    def test_custom_rule_namespace(self):
        filename = "malware_rules.yar"
        base = os.path.splitext(filename)[0]
        namespace = f"custom__{base}"
        assert namespace == "custom__malware_rules"

    def test_community_rule_namespace(self):
        rel_path = os.path.join("community", "neo23x0")
        filename = "apt_apt10.yar"
        base = os.path.splitext(filename)[0]
        prefix = rel_path.replace(os.sep, "__")
        namespace = f"{prefix}__{base}"
        assert namespace == "community__neo23x0__apt_apt10"

    def test_no_collision_between_custom_and_community(self):
        ns_custom = "custom__malware_rules"
        ns_community = "community__neo23x0__malware_rules"
        assert ns_custom != ns_community


# ---------------------------------------------------------------------------
# File Scanner Integration Tests (4)
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not HAS_YARA, reason="yara-python not installed")
class TestFileScannerIntegration:
    """_load_yara_rules handles custom + community + disabled + broken."""

    def test_load_custom_and_community(self, tmp_path):
        """Both custom (root) and community (subdir) rules are loaded."""
        (tmp_path / "custom_test.yar").write_text(VALID_YARA)
        community = tmp_path / "community" / "neo23x0"
        community.mkdir(parents=True)
        (community / "apt_test.yar").write_text(VALID_YARA_B)
        (tmp_path / "disabled_rules.txt").write_text("# empty\n")

        from scanners.file_scanner import _load_yara_rules

        rules = _load_yara_rules(str(tmp_path))
        assert rules is not None

    def test_disabled_rule_skipped(self, tmp_path):
        """A rule listed in disabled_rules.txt is not loaded."""
        (tmp_path / "apt_disabled.yar").write_text(VALID_YARA)
        (tmp_path / "disabled_rules.txt").write_text("apt_disabled.yar\n")

        from scanners.file_scanner import _load_yara_rules

        rules = _load_yara_rules(str(tmp_path))
        assert rules is None  # only rule is disabled → nothing to load

    def test_broken_dir_skipped(self, tmp_path):
        """_broken/ directory is never walked."""
        (tmp_path / "good.yar").write_text(VALID_YARA)
        broken = tmp_path / "_broken"
        broken.mkdir()
        (broken / "bad.yar").write_text(BROKEN_YARA)
        (tmp_path / "disabled_rules.txt").write_text("")

        from scanners.file_scanner import _load_yara_rules

        rules = _load_yara_rules(str(tmp_path))
        assert rules is not None  # good.yar loaded, _broken/ ignored

    def test_phase_b_fallback(self, tmp_path):
        """If batch compile fails, per-file compile rescues valid rules."""
        (tmp_path / "good.yar").write_text(VALID_YARA)
        (tmp_path / "bad.yar").write_text(BROKEN_YARA)
        (tmp_path / "disabled_rules.txt").write_text("")

        from scanners.file_scanner import _load_yara_rules

        rules = _load_yara_rules(str(tmp_path))
        assert rules is not None  # good.yar loaded via Phase B


# ---------------------------------------------------------------------------
# Metadata Tests (3)
# ---------------------------------------------------------------------------

class TestMetadata:
    """_metadata.json round-trip and schema."""

    def test_metadata_roundtrip(self, tmp_path):
        meta_path = tmp_path / "_metadata.json"
        data = {"source": "test", "rules_count": 42, "broken_count": 3}
        with open(meta_path, "w") as f:
            json.dump(data, f)
        loaded = json.loads(meta_path.read_text())
        assert loaded["rules_count"] == 42
        assert loaded["broken_count"] == 3

    def test_metadata_has_timestamp_format(self):
        from datetime import datetime, timezone

        ts = datetime.now(timezone.utc).isoformat()
        assert "T" in ts
        assert "+" in ts or "Z" in ts  # timezone info present

    def test_metadata_overwrite(self, tmp_path):
        meta_path = tmp_path / "_metadata.json"
        with open(meta_path, "w") as f:
            json.dump({"v": 1}, f)
        with open(meta_path, "w") as f:
            json.dump({"v": 2}, f)
        assert json.loads(meta_path.read_text())["v"] == 2


# ---------------------------------------------------------------------------
# get_yara_info Tests (2)
# ---------------------------------------------------------------------------

class TestGetYaraInfo:
    """get_yara_info returns correct counts and metadata."""

    def test_custom_only(self, tmp_path):
        """When no community rules exist, only custom entry returned."""
        from ioc_updater import get_yara_info

        (tmp_path / "test.yar").write_text(VALID_YARA)
        info = get_yara_info(str(tmp_path))
        assert len(info) >= 1
        assert info[0]["source"] == "Custom (corvus)"
        assert info[0]["count"] == 1

    def test_with_community_and_metadata(self, tmp_path):
        """Community rules with metadata show correct info."""
        from ioc_updater import get_yara_info

        (tmp_path / "test.yar").write_text(VALID_YARA)
        community = tmp_path / "community" / "neo23x0"
        community.mkdir(parents=True)
        (community / "apt_a.yar").write_text(VALID_YARA)
        (community / "apt_b.yar").write_text(VALID_YARA_B)
        meta = {
            "source": "Neo23x0 signature-base",
            "last_updated": "2026-03-19T10:00:00+00:00",
            "rules_count": 2,
            "broken_count": 0,
        }
        with open(community / "_metadata.json", "w") as f:
            json.dump(meta, f)

        info = get_yara_info(str(tmp_path))
        assert len(info) >= 2
        # Community entry
        comm_entry = [e for e in info if "neo23x0" in e["source"]][0]
        assert comm_entry["count"] == 2
        assert "2 valid" in comm_entry["status"]
