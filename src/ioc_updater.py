"""
ioc_updater.py - IOC (Indicator of Compromise) automatic update module.

Fetches IOC feeds from free, public threat intelligence sources and merges
them with existing local IOC files.  Uses only ``urllib`` (stdlib) — no
extra dependencies needed for Nuitka single-exe builds.

Sources (all free, no authentication required):
  - Feodo Tracker (abuse.ch)  → bad_ips.txt
  - URLhaus (abuse.ch)        → bad_domains.txt
  - MalwareBazaar (abuse.ch)  → bad_hashes.txt

Design:
  - Existing manual entries (lines with ``# [MANUAL]`` or plain entries
    already in the file) are NEVER removed.
  - Each update writes a metadata header so ``--ioc-info`` can display
    the last-update timestamp, source, and entry count.
  - If a remote source is unreachable the updater logs the error and
    continues with the remaining sources.
"""

import os
import re
import io
import ssl
import json
import shutil
import zipfile
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple
from urllib.request import urlopen, Request
from urllib.error import URLError
from urllib.parse import urlparse

from scanner_core.utils import get_resource_path


# ---------------------------------------------------------------------------
# Feed Definitions
# ---------------------------------------------------------------------------

IOC_FEEDS: List[Dict] = [
    {
        "name": "Feodo Tracker (abuse.ch)",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "target": "bad_ips.txt",
        "ioc_type": "Malicious IPs",
        "parser": "_parse_plain_lines",
    },
    {
        "name": "URLhaus (abuse.ch)",
        "url": "https://urlhaus.abuse.ch/downloads/text_online/",
        "target": "bad_domains.txt",
        "ioc_type": "Malicious Domains",
        "parser": "_parse_urlhaus_domains",
    },
    {
        "name": "MalwareBazaar (abuse.ch)",
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "target": "bad_hashes.txt",
        "ioc_type": "Malicious Hashes (SHA256)",
        "parser": "_parse_plain_lines",
    },
]

_TIMEOUT = 30  # seconds per HTTP request
_USER_AGENT = "Corvus-IOC-Updater/1.0"

# JSON-based feeds (separate from text-based IOC_FEEDS)
JSON_FEEDS = [
    {
        "name": "CISA KEV (Known Exploited Vulnerabilities)",
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "target": "cve_database.json",
        "ioc_type": "CVE Database",
    },
]

# ---------------------------------------------------------------------------
# YARA Rule Feeds
# ---------------------------------------------------------------------------

YARA_FEEDS: List[Dict] = [
    {
        "name": "Neo23x0 signature-base",
        "url": "https://github.com/Neo23x0/signature-base/archive/refs/heads/master.zip",
        "source_subdir": "signature-base-master/yara",
        "target_subdir": "community/neo23x0",
        "include_prefixes": ("apt_", "crime_"),
        "exclude_files": {
            # THOR-specific: external variable dependencies → compile errors
            "thor_inverse_matches.yar",
            "generic_anomalies.yar",
            "general_cloaking.yar",
            "yara_mixed_ext_vars.yar",
            "gen_webshells_ext_vars.yar",
        },
        "exclude_prefixes": ("thor-", "thor_"),
    },
]

_YARA_TIMEOUT = 90  # seconds — ZIP download is larger than text feeds


# Metadata header written at the top of each IOC file after update
_HEADER_TEMPLATE = """\
# ============================================================
# Corvus IOC Database
# Type: {ioc_type}
# Updated: {timestamp}
# Sources: {sources}
# Count: {count} entries
# ============================================================
"""


# ---------------------------------------------------------------------------
# Parsers — extract IOC entries from raw feed text
# ---------------------------------------------------------------------------

def _parse_plain_lines(raw: str) -> Set[str]:
    """Parse a simple text feed: one entry per line, # = comment."""
    entries: Set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.add(line.lower())
    return entries


def _parse_urlhaus_domains(raw: str) -> Set[str]:
    """Parse URLhaus text feed → extract unique domains from URLs."""
    domains: Set[str] = set()
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            parsed = urlparse(line)
            host = parsed.hostname
            if host:
                # Strip port and normalize
                host = host.lower().strip(".")
                # Skip raw IPs — we want domains only
                if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host):
                    domains.add(host)
        except Exception:
            continue
    return domains


# Dispatch table (avoids eval)
_PARSERS = {
    "_parse_plain_lines": _parse_plain_lines,
    "_parse_urlhaus_domains": _parse_urlhaus_domains,
}


# ---------------------------------------------------------------------------
# CISA KEV → cve_database.json merge
# ---------------------------------------------------------------------------

def _merge_cisa_kev_into_cve_db(kev_json: str, cve_db_path: str) -> Tuple[int, int]:
    """Merge CISA Known Exploited Vulnerabilities into the CVE database.

    Adds new CVEs from the CISA KEV feed as a "CISA KEV" software group.
    Existing manual entries are preserved.  Duplicate CVE IDs are skipped.

    Args:
        kev_json: Raw JSON string from the CISA KEV feed.
        cve_db_path: Path to the local cve_database.json file.

    Returns:
        Tuple of (before_count, after_count).
    """
    try:
        kev_data = json.loads(kev_json)
    except (json.JSONDecodeError, ValueError):
        raise ValueError("Cannot parse CISA KEV JSON")

    vulnerabilities = kev_data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise ValueError("CISA KEV feed has no vulnerabilities")

    # Load existing CVE database (or create skeleton)
    existing: Dict = {
        "version": datetime.now().strftime("%Y-%m-%d"),
        "description": "Offline CVE database for endpoint vulnerability scanning",
        "entries": [],
    }
    try:
        with open(cve_db_path, "r", encoding="utf-8") as f:
            existing = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        pass

    # Collect all existing CVE IDs to avoid duplicates
    existing_cve_ids: Set[str] = set()
    for entry in existing.get("entries", []):
        for cve in entry.get("cves", []):
            existing_cve_ids.add(cve.get("id", "").upper())

    before_count = len(existing_cve_ids)

    # Parse CISA KEV entries into our format
    new_cves: List[Dict] = []
    for vuln in vulnerabilities:
        cve_id = vuln.get("cveID", "").upper()
        if not cve_id or cve_id in existing_cve_ids:
            continue

        # Map CISA severity to our format
        new_cves.append({
            "id": cve_id,
            "name": vuln.get("vulnerabilityName", cve_id),
            "severity": "HIGH",  # All KEV entries are actively exploited
            "cvss": 0.0,  # CISA KEV doesn't include CVSS
            "affected": vuln.get("product", "Unknown"),
            "description": (
                f"{vuln.get('shortDescription', 'Known exploited vulnerability.')} "
                f"[CISA KEV - Due: {vuln.get('dueDate', 'N/A')}]"
            ),
            "kb_fix": "",
        })
        existing_cve_ids.add(cve_id)

    if new_cves:
        # Find or create the CISA KEV entry group
        kev_group = None
        for entry in existing.get("entries", []):
            if entry.get("software") == "CISA KEV (Known Exploited)":
                kev_group = entry
                break

        if kev_group is None:
            kev_group = {
                "software": "CISA KEV (Known Exploited)",
                "pattern": "__cisa_kev__",
                "cves": [],
            }
            existing["entries"].append(kev_group)

        kev_group["cves"].extend(new_cves)

    # Update version timestamp
    existing["version"] = datetime.now().strftime("%Y-%m-%d")

    after_count = len(existing_cve_ids)

    # Write back
    os.makedirs(os.path.dirname(cve_db_path), exist_ok=True)
    with open(cve_db_path, "w", encoding="utf-8") as f:
        json.dump(existing, f, indent=2, ensure_ascii=False)

    return before_count, after_count


# ---------------------------------------------------------------------------
# File I/O — read existing, merge, write back
# ---------------------------------------------------------------------------

def _read_existing_entries(filepath: str) -> Tuple[Set[str], bool]:
    """Read existing IOC file and return (entries, has_manual_marker).

    Manual entries are preserved during merge.  The ``has_manual`` flag
    indicates whether any ``# [MANUAL]`` comments were found.
    """
    entries: Set[str] = set()
    has_manual = False
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                if "# [MANUAL]" in stripped:
                    has_manual = True
                if stripped and not stripped.startswith("#"):
                    entries.add(stripped.lower())
    except FileNotFoundError:
        pass
    return entries, has_manual


def _read_manual_comments(filepath: str) -> str:
    """Extract user-created comment lines for preservation.

    Only comment lines (starting with ``#``) are returned — actual data
    entries are already captured by ``_read_existing_entries`` and merged
    into the sorted output, so they must NOT be included here to avoid
    writing entries twice.

    Auto-generated metadata header lines are excluded.
    """
    _HEADER_PREFIXES = (
        "# Corvus IOC Database", "# Type:", "# Updated:",
        "# Sources:", "# Count:", "# ====",
    )
    comment_lines: List[str] = []
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            for line in f:
                stripped = line.strip()
                # Skip auto-generated metadata header
                if any(stripped.startswith(p) for p in _HEADER_PREFIXES):
                    continue
                # Skip empty lines and non-comments
                if not stripped or not stripped.startswith("#"):
                    continue
                # Keep user-created comment lines (section markers, notes)
                comment_lines.append(stripped)
    except FileNotFoundError:
        pass
    return "\n".join(comment_lines)


def _write_ioc_file(filepath: str, entries: Set[str], ioc_type: str,
                     sources: str, manual_block: str = "") -> int:
    """Write IOC file with metadata header, optional manual block, and entries.

    Returns the total entry count written.
    """
    # Ensure parent directory exists
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    # Sort for deterministic output
    sorted_entries = sorted(entries)
    count = len(sorted_entries)

    header = _HEADER_TEMPLATE.format(
        ioc_type=ioc_type,
        timestamp=timestamp,
        sources=sources,
        count=count,
    )

    with open(filepath, "w", encoding="utf-8", newline="\n") as f:
        f.write(header)
        if manual_block.strip():
            f.write("\n")
            f.write(manual_block)
            f.write("\n\n")
        # Write sorted entries — one per line
        f.write("\n".join(sorted_entries))
        if sorted_entries:
            f.write("\n")

    return count


# ---------------------------------------------------------------------------
# Network — fetch remote feed
# ---------------------------------------------------------------------------

def _fetch_feed(url: str, timeout: int = _TIMEOUT) -> Optional[str]:
    """Download a text feed from a URL.  Returns raw text or None on error."""
    try:
        # Create SSL context that works in corporate/restricted environments
        ctx = ssl.create_default_context()
        req = Request(url, headers={"User-Agent": _USER_AGENT})
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except (URLError, OSError, ValueError) as e:
        print(f"  [!] Failed to fetch {url}: {e}")
        return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def update_all_iocs(ioc_dir: Optional[str] = None) -> Dict:
    """Fetch all IOC feeds, merge with existing files, and write back.

    Args:
        ioc_dir: Path to the ``iocs/`` directory.  If *None* the default
                 Corvus resource path is used.

    Returns:
        A summary dict with per-file results::

            {
                "updated": [{"file": ..., "before": N, "after": M, "source": ...}, ...],
                "failed": [{"file": ..., "source": ..., "error": ...}, ...],
                "timestamp": "2026-03-15T14:30:00",
            }
    """
    if ioc_dir is None:
        ioc_dir = get_resource_path("iocs")

    # Ensure the iocs directory exists (Nuitka onefile may not extract
    # an empty directory, and first-time updates need to create files)
    os.makedirs(ioc_dir, exist_ok=True)

    results: Dict = {
        "updated": [],
        "failed": [],
        "timestamp": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
    }

    for feed in IOC_FEEDS:
        filepath = os.path.join(ioc_dir, feed["target"])
        source_name = feed["name"]

        print(f"  [*] Fetching {source_name}...")

        # 1. Read existing entries
        existing, _ = _read_existing_entries(filepath)
        before_count = len(existing)

        # 2. Preserve manual entry blocks
        manual_block = _read_manual_comments(filepath)

        # 3. Fetch remote feed
        raw = _fetch_feed(feed["url"])
        if raw is None:
            results["failed"].append({
                "file": feed["target"],
                "source": source_name,
                "error": "Network error or timeout",
            })
            continue

        # 4. Parse fetched entries
        parser_fn = _PARSERS[feed["parser"]]
        new_entries = parser_fn(raw)

        if not new_entries:
            print(f"  [!] {source_name}: no entries parsed (empty feed?)")
            results["failed"].append({
                "file": feed["target"],
                "source": source_name,
                "error": "Empty feed — 0 entries parsed",
            })
            continue

        # 5. Merge: union of existing + new
        merged = existing | new_entries
        after_count = len(merged)

        # 6. Write back
        sources_str = f"{source_name} + manual"
        _write_ioc_file(filepath, merged, feed["ioc_type"], sources_str, manual_block)

        added = after_count - before_count
        print(f"  [+] {feed['target']:<20}: {before_count} → {after_count} entries (+{added} new)")

        results["updated"].append({
            "file": feed["target"],
            "before": before_count,
            "after": after_count,
            "added": added,
            "source": source_name,
        })

    # ---- JSON-based feeds (CISA KEV → CVE database) ----
    for feed in JSON_FEEDS:
        filepath = os.path.join(ioc_dir, feed["target"])
        source_name = feed["name"]

        print(f"  [*] Fetching {source_name}...")

        raw = _fetch_feed(feed["url"])
        if raw is None:
            results["failed"].append({
                "file": feed["target"],
                "source": source_name,
                "error": "Network error or timeout",
            })
            continue

        try:
            before, after = _merge_cisa_kev_into_cve_db(raw, filepath)
            added = after - before
            print(f"  [+] {feed['target']:<20}: {before} \u2192 {after} CVEs (+{added} new)")
            results["updated"].append({
                "file": feed["target"],
                "before": before,
                "after": after,
                "added": added,
                "source": source_name,
            })
        except (ValueError, OSError) as e:
            print(f"  [!] {source_name}: {e}")
            results["failed"].append({
                "file": feed["target"],
                "source": source_name,
                "error": str(e),
            })

    # ---- YARA Community Rules ----
    print(f"\n  {'─'*55}")
    print(f"  YARA COMMUNITY RULES")
    print(f"  {'─'*55}")
    yara_summary = update_yara_rules()
    results["yara"] = yara_summary
    if yara_summary["feeds_processed"] > 0:
        print(f"\n  [+] YARA: {yara_summary['rules_valid']} valid, "
              f"{yara_summary['rules_broken']} broken")

    return results


def get_ioc_info(ioc_dir: Optional[str] = None) -> List[Dict]:
    """Read metadata from IOC files and return a list of info dicts.

    Returns a list of dicts, one per IOC file::

        [
            {
                "file": "bad_ips.txt",
                "updated": "2026-03-15T14:30:00",
                "sources": "Feodo Tracker (abuse.ch) + manual",
                "count": 245,
                "ioc_type": "Malicious IPs",
            },
            ...
        ]
    """
    if ioc_dir is None:
        ioc_dir = get_resource_path("iocs")

    info_list: List[Dict] = []

    # Text-based IOC files
    text_files = [
        ("bad_ips.txt", "Malicious IPs"),
        ("bad_domains.txt", "Malicious Domains"),
        ("bad_hashes.txt", "Malicious Hashes"),
    ]

    for filename, default_type in text_files:
        filepath = os.path.join(ioc_dir, filename)
        entry: Dict = {
            "file": filename,
            "updated": "Never",
            "sources": "manual",
            "count": 0,
            "ioc_type": default_type,
        }

        try:
            with open(filepath, "r", encoding="utf-8") as f:
                entry_count = 0
                for line in f:
                    stripped = line.strip()
                    # Parse metadata header
                    if stripped.startswith("# Updated:"):
                        entry["updated"] = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("# Sources:"):
                        entry["sources"] = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("# Type:"):
                        entry["ioc_type"] = stripped.split(":", 1)[1].strip()
                    elif stripped.startswith("# Count:"):
                        # Parse "N entries" from header
                        match = re.search(r"(\d+)", stripped)
                        if match:
                            pass  # We'll count actual entries below
                    elif stripped and not stripped.startswith("#"):
                        entry_count += 1
                entry["count"] = entry_count
        except FileNotFoundError:
            entry["updated"] = "File not found"
        info_list.append(entry)

    # JSON-based IOC files
    json_files = [
        ("cve_database.json", "CVE Database"),
        ("malware_signatures.json", "Malware Signatures"),
    ]

    for filename, default_type in json_files:
        filepath = os.path.join(ioc_dir, filename)
        entry: Dict = {
            "file": filename,
            "updated": "Unknown",
            "sources": "manual",
            "count": 0,
            "ioc_type": default_type,
        }
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                data = json.load(f)
            # CVE database
            if "version" in data:
                entry["updated"] = data["version"]
            if "entries" in data:
                entry["count"] = sum(len(e.get("cves", [])) for e in data["entries"])
            elif "signatures" in data:
                entry["count"] = len(data.get("signatures", []))
                entry["count"] += len(data.get("memory_signatures", []))
        except (FileNotFoundError, json.JSONDecodeError):
            entry["updated"] = "File not found / error"
        info_list.append(entry)

    return info_list


def show_ioc_info(ioc_dir: Optional[str] = None,
                   yara_dir: Optional[str] = None) -> None:
    """Print IOC database status to console."""
    info_list = get_ioc_info(ioc_dir)

    print(f"\n  IOC Database Status")
    print(f"  {'='*60}")
    print(f"  {'File':<26} {'Updated':<22} {'Count':<8} Source")
    print(f"  {'-'*26} {'-'*22} {'-'*8} {'-'*20}")

    for entry in info_list:
        updated = entry["updated"]
        # Truncate long timestamps
        if len(updated) > 20:
            updated = updated[:19]
        count_str = str(entry["count"])
        source = entry["sources"]
        if len(source) > 20:
            source = source[:18] + ".."
        print(f"  {entry['file']:<26} {updated:<22} {count_str:<8} {source}")

    # ---- YARA Rules Section ----
    yara_info = get_yara_info(yara_dir)
    if yara_info:
        print(f"\n  YARA Rule Status")
        print(f"  {'='*60}")
        print(f"  {'Source':<26} {'Updated':<22} {'Count':<8} Status")
        print(f"  {'-'*26} {'-'*22} {'-'*8} {'-'*20}")
        for entry in yara_info:
            updated = entry["updated"]
            if len(updated) > 20:
                updated = updated[:19]
            print(f"  {entry['source']:<26} {updated:<22} {entry['count']:<8} {entry['status']}")

    print()


# ---------------------------------------------------------------------------
# YARA Rule Download & Management
# ---------------------------------------------------------------------------

def _fetch_zip(url: str, timeout: int = _YARA_TIMEOUT) -> Optional[bytes]:
    """Download a ZIP archive as bytes.  Returns *None* on error."""
    print(f"  [*] Downloading rules archive...")
    try:
        ctx = ssl.create_default_context()
        req = Request(url, headers={"User-Agent": _USER_AGENT})
        with urlopen(req, timeout=timeout, context=ctx) as resp:
            data = resp.read()
            size_mb = len(data) / (1024 * 1024)
            print(f"  [+] Downloaded {size_mb:.1f} MB")
            return data
    except (URLError, TimeoutError, OSError) as e:
        print(f"  [!] Download failed: {e}")
        return None


def _extract_yara_from_zip(zip_bytes: bytes, feed: Dict,
                            yara_dir: str) -> Tuple[int, int]:
    """Extract filtered YARA rules from a ZIP archive.

    Applies include-prefix, exclude-file, and exclude-prefix filters.
    Wipes and recreates ``target_subdir`` for idempotent updates.

    Returns:
        ``(previous_count, new_count)`` of ``.yar`` files.
    """
    target_dir = os.path.join(yara_dir, feed["target_subdir"])
    source_subdir = feed["source_subdir"]
    include_prefixes = feed["include_prefixes"]
    exclude_files = feed.get("exclude_files", set())
    exclude_prefixes = feed.get("exclude_prefixes", ())

    # Count existing rules before wipe
    previous_count = 0
    if os.path.isdir(target_dir):
        previous_count = len([f for f in os.listdir(target_dir)
                              if f.endswith(".yar")])
        shutil.rmtree(target_dir)

    os.makedirs(target_dir, exist_ok=True)

    new_count = 0
    skipped = 0

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for entry in zf.namelist():
            # Must be directly inside source YARA directory
            if not entry.startswith(source_subdir + "/"):
                continue
            if not entry.endswith(".yar"):
                continue

            filename = os.path.basename(entry)
            if not filename:
                continue

            # Exclude specific files (THOR-specific, FP-prone)
            if filename in exclude_files:
                skipped += 1
                continue

            # Exclude by prefix (thor-*, thor_*)
            if any(filename.startswith(p) for p in exclude_prefixes):
                skipped += 1
                continue

            # Include only matching prefixes (apt_*, crime_*)
            if not any(filename.startswith(p) for p in include_prefixes):
                skipped += 1
                continue

            # Read once, write from buffer
            try:
                content = zf.read(entry)
            except Exception:
                skipped += 1
                continue

            out_path = os.path.join(target_dir, filename)
            with open(out_path, "wb") as f:
                f.write(content)
            new_count += 1

    print(f"  [+] Extracted {new_count} rules ({skipped} filtered out)")
    return previous_count, new_count


def _validate_yara_rules(yara_dir: str, subdir: str) -> Tuple[int, int]:
    """Compile-test each YARA rule file individually.

    Broken rules are moved to a ``_broken/`` subdirectory (not deleted)
    so the user can inspect them.

    Returns:
        ``(valid_count, broken_count)``.
    """
    try:
        import yara  # noqa: F811 — lazy import, not always available
    except ImportError:
        print("  [!] yara-python not installed — skipping validation")
        return (0, 0)

    rules_path = os.path.join(yara_dir, subdir)
    if not os.path.isdir(rules_path):
        return (0, 0)

    broken_dir = os.path.join(rules_path, "_broken")
    valid = 0
    broken = 0

    for filename in sorted(os.listdir(rules_path)):
        if not filename.endswith(".yar"):
            continue

        filepath = os.path.join(rules_path, filename)
        try:
            yara.compile(filepath=filepath)
            valid += 1
        except yara.SyntaxError as e:
            os.makedirs(broken_dir, exist_ok=True)
            shutil.move(filepath, os.path.join(broken_dir, filename))
            print(f"  [!] Broken → _broken/{filename}: {e}")
            broken += 1
        except Exception:
            os.makedirs(broken_dir, exist_ok=True)
            shutil.move(filepath, os.path.join(broken_dir, filename))
            broken += 1

    print(f"  [i] Validation: {valid} valid, {broken} broken")
    return valid, broken


def update_yara_rules(yara_dir: Optional[str] = None) -> Dict:
    """Download, extract, and validate community YARA rules.

    Returns a summary dict::

        {
            "feeds_processed": 1,
            "rules_downloaded": 85,
            "rules_valid": 82,
            "rules_broken": 3,
        }
    """
    if yara_dir is None:
        yara_dir = get_resource_path("yara_rules")

    os.makedirs(yara_dir, exist_ok=True)

    summary: Dict = {
        "feeds_processed": 0,
        "rules_downloaded": 0,
        "rules_valid": 0,
        "rules_broken": 0,
    }

    for feed in YARA_FEEDS:
        print(f"\n  [*] Processing: {feed['name']}")

        # 1. Download ZIP
        zip_bytes = _fetch_zip(feed["url"])
        if not zip_bytes:
            continue

        # 2. Extract filtered rules
        prev_count, new_count = _extract_yara_from_zip(
            zip_bytes, feed, yara_dir)
        summary["rules_downloaded"] += new_count

        # 3. Validate each rule individually
        valid, broken = _validate_yara_rules(yara_dir, feed["target_subdir"])
        summary["rules_valid"] += valid
        summary["rules_broken"] += broken

        # 4. Write metadata
        meta_path = os.path.join(
            yara_dir, feed["target_subdir"], "_metadata.json")
        metadata = {
            "source": feed["name"],
            "url": feed["url"],
            "last_updated": datetime.now(timezone.utc).isoformat(),
            "rules_count": valid,
            "broken_count": broken,
        }
        try:
            with open(meta_path, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
        except OSError:
            pass

        summary["feeds_processed"] += 1

    return summary


def get_yara_info(yara_dir: Optional[str] = None) -> List[Dict]:
    """Collect YARA rule status for ``--ioc-info`` display.

    Returns a list of dicts with ``source``, ``updated``, ``count``,
    and ``status`` keys.
    """
    if yara_dir is None:
        yara_dir = get_resource_path("yara_rules")

    info: List[Dict] = []

    # Custom rules (root level .yar files)
    custom_count = 0
    if os.path.isdir(yara_dir):
        custom_count = len([f for f in os.listdir(yara_dir)
                            if f.endswith(".yar")])
    info.append({
        "source": "Custom (corvus)",
        "updated": "Built-in",
        "count": custom_count,
        "status": "active",
    })

    # Community rules (subdirectories)
    community_base = os.path.join(yara_dir, "community")
    if os.path.isdir(community_base):
        for source_name in sorted(os.listdir(community_base)):
            source_dir = os.path.join(community_base, source_name)
            if not os.path.isdir(source_dir):
                continue

            meta_path = os.path.join(source_dir, "_metadata.json")
            entry: Dict = {
                "source": f"Community ({source_name})",
                "updated": "Never",
                "count": 0,
                "status": "not downloaded",
            }

            # Count .yar files (excluding _broken/)
            rule_count = len([f for f in os.listdir(source_dir)
                              if f.endswith(".yar")])
            entry["count"] = rule_count

            # Read metadata
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                entry["updated"] = meta.get("last_updated", "Unknown")[:19]
                entry["status"] = (
                    f"{meta.get('rules_count', 0)} valid, "
                    f"{meta.get('broken_count', 0)} broken"
                )
            except (FileNotFoundError, json.JSONDecodeError):
                pass

            info.append(entry)

    # Disabled rules count
    disabled_path = os.path.join(yara_dir, "disabled_rules.txt")
    disabled_count = 0
    try:
        with open(disabled_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    disabled_count += 1
    except FileNotFoundError:
        pass

    if disabled_count > 0:
        info.append({
            "source": "Disabled rules",
            "updated": "—",
            "count": disabled_count,
            "status": "disabled_rules.txt",
        })

    return info
