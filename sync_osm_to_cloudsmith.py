#!/usr/bin/env python3
"""
Sync malicious packages AND container images (ALL severity levels) from
OpenSourceMalware.com into a Cloudsmith EPM "Exact Blocklist" Rego policy.

Designed to run as a GitHub Actions scheduled workflow (hourly).

Uses the official OSM API (api.opensourcemalware.com) with a personal osm_
token. Unlike the old internal feed, the official API returns *recent*
threats per ecosystem rather than the whole database, so this script keeps a
record store (STATE_FILE) and merges each run's results into it. When no
store exists yet (first run after migration, or the state file isn't
persisted between runs), the store is seeded from the blocklist already in
your Cloudsmith policy so existing blocks are never dropped.

Environment variables required:
  OSM_API_KEY              - OpenSourceMalware API token (osm_...)
  CLOUDSMITH_API_KEY       - Your Cloudsmith API key
  CLOUDSMITH_WORKSPACE     - Your Cloudsmith workspace slug
  CLOUDSMITH_POLICY_SLUG   - The slug_perm of your "Exact Blocklist" EPM policy

Optional:
  OSM_FEED                 - "query-latest" (default; free tier, latest 100
                             verified threats per ecosystem per call) or
                             "threat-feed" (paid Core/Enterprise tier;
                             rolling time window, no 100-record cap)
  OSM_LOOKBACK_HOURS       - threat-feed lookback window, 1-24 (default 2).
                             Must be longer than the time between runs.
  OSM_ECOSYSTEMS           - Comma-separated OSM ecosystems to poll
                             (default: npm,pypi,crates,nuget,maven,go,
                             packagist,rubygems,container)
  STATE_FILE               - Record store path (default last_known_packages.json)
  OVERLAP_REPORT_FILE      - OSV overlap history (default osv_overlap_report.json)
  MAX_SHRINK_PCT           - Abort instead of updating the policy if the
                             blocklist would shrink by more than this
                             percentage (default 20)
"""

import copy
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OSM_API_BASE = "https://api.opensourcemalware.com/functions/v1"
OSM_API_KEY = os.environ.get("OSM_API_KEY", "").strip()
OSM_FEED = os.environ.get("OSM_FEED", "query-latest").strip().lower()
OSM_LOOKBACK_HOURS = int(os.environ.get("OSM_LOOKBACK_HOURS", "2"))
DEFAULT_ECOSYSTEMS = "npm,pypi,crates,nuget,maven,go,packagist,rubygems,container"
OSM_ECOSYSTEMS = [
    e.strip().lower()
    for e in os.environ.get("OSM_ECOSYSTEMS", DEFAULT_ECOSYSTEMS).split(",")
    if e.strip()
]
QUERY_LATEST_LIMIT = 100  # query-latest returns at most this many per call

CLOUDSMITH_API_BASE = "https://api.cloudsmith.io/v2"
CLOUDSMITH_API_KEY = os.environ.get("CLOUDSMITH_API_KEY", "")
CLOUDSMITH_WORKSPACE = os.environ.get("CLOUDSMITH_WORKSPACE", "")
CLOUDSMITH_POLICY_SLUG = os.environ.get("CLOUDSMITH_POLICY_SLUG", "")

STATE_FILE = os.environ.get("STATE_FILE", "last_known_packages.json")
OVERLAP_REPORT_FILE = os.environ.get("OVERLAP_REPORT_FILE", "osv_overlap_report.json")
MAX_SHRINK_PCT = float(os.environ.get("MAX_SHRINK_PCT", "20"))

STORE_SCHEMA = 2

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

# OSM registry/ecosystem name -> Cloudsmith package format
REGISTRY_TO_FORMAT = {
    "npm": "npm",
    "pypi": "python",
    "maven": "maven",
    "nuget": "nuget",
    "rubygems": "ruby",
    "go": "go",
    "cargo": "cargo",
    "crates": "cargo",
    "packagist": "php",
    "hex": "hex",
    "cocoapods": "cocoapods",
    "pub": "dart",
    "dockerhub": "docker",
    "docker": "docker",
    "container": "docker",
}


class OSMError(Exception):
    """Raised for OSM API failures that need a human to act (auth, tier)."""


# ---------------------------------------------------------------------------
# 1. Fetch threats from the official OSM API
# ---------------------------------------------------------------------------
def _osm_get(endpoint: str, params: dict) -> dict:
    """GET an OSM endpoint with Bearer auth, retrying on 429/5xx."""
    url = f"{OSM_API_BASE}/{endpoint}"
    headers = {"Authorization": f"Bearer {OSM_API_KEY}"}
    resp = None
    for attempt in range(1, 5):
        resp = requests.get(url, params=params, headers=headers, timeout=60)

        if resp.status_code == 429 or resp.status_code >= 500:
            try:
                wait = int(resp.headers.get("Retry-After", ""))
            except ValueError:
                wait = 5 * 2 ** attempt
            log.warning(f"  OSM {endpoint} returned {resp.status_code}; retrying in {wait}s")
            time.sleep(wait)
            continue

        if resp.status_code == 401:
            raise OSMError(
                f"OSM rejected the API token (401): {resp.text.strip()}. "
                "Check that the OSM_API_KEY secret is set, starts with osm_, "
                "and hasn't been revoked."
            )
        if resp.status_code == 403:
            hint = ""
            if endpoint == "threat-feed":
                hint = (
                    " threat-feed requires a paid Core/Enterprise OSM plan; "
                    "set OSM_FEED=query-latest to use the free endpoint."
                )
            raise OSMError(f"OSM denied access to {endpoint} (403): {resp.text.strip()}.{hint}")

        resp.raise_for_status()
        return resp.json()

    resp.raise_for_status()
    return {}


def fetch_osm_threats() -> tuple[list[dict], list[dict], list[str]]:
    """
    Poll each configured ecosystem. Returns (packages, containers,
    ecosystems_that_may_have_gaps).
    """
    packages: list[dict] = []
    containers: list[dict] = []
    possible_gaps: list[str] = []

    log.info(f"Fetching threats from OSM ({OSM_FEED}) for: {', '.join(OSM_ECOSYSTEMS)}")
    for eco in OSM_ECOSYSTEMS:
        if OSM_FEED == "threat-feed":
            data = _osm_get("threat-feed", {"ecosystem": eco, "hours": OSM_LOOKBACK_HOURS})
            window = f" ({data.get('from')} -> {data.get('to')})"
        else:
            data = _osm_get("query-latest", {"ecosystem": eco})
            window = ""

        threats = data.get("threats") or []
        log.info(f"  {eco}: {len(threats)} verified threats{window}")

        if OSM_FEED == "query-latest" and len(threats) >= QUERY_LATEST_LIMIT:
            possible_gaps.append(eco)
            log.warning(
                f"  {eco} hit the {QUERY_LATEST_LIMIT}-record cap; threats verified "
                "since the last run may have been missed. Run more often, or use "
                "OSM_FEED=threat-feed if you have a paid OSM plan."
            )

        for t in threats:
            item = _normalize_threat(t, eco)
            if item is None:
                continue
            (containers if item["type"] == "container" else packages).append(item)

    log.info(f"  Fetched {len(packages)} package and {len(containers)} container entries")
    return packages, containers, possible_gaps


def _normalize_threat(t: dict, eco: str) -> dict | None:
    """Convert an OSM threat record into this script's internal item shape."""
    if t.get("status") and t["status"] != "verified":
        return None

    report_type = (t.get("report_type") or "").lower()
    if report_type not in ("package", "container"):
        return None

    name = t.get("package_name") or ""
    if report_type == "container" and not name:
        name = t.get("resource_identifier") or ""
    if not name:
        return None

    registry = (t.get("registry") or eco or "").lower()
    if report_type == "container":
        fmt = REGISTRY_TO_FORMAT.get(registry, "docker")
    else:
        fmt = REGISTRY_TO_FORMAT.get(registry, registry)

    return {
        "id": t.get("id") or f"{report_type}:{fmt}:{name}",
        "format": fmt,
        "name": name,
        "severity": t.get("severity_level") or "unknown",
        "versions": _parse_versions(t.get("version_info") or ""),
        "type": report_type,
        "osv_url": t.get("osv_advisory_url") or None,
        "last_updated": t.get("last_updated") or t.get("updated_at"),
        "legacy": False,
    }


# ---------------------------------------------------------------------------
# 2. Version parsing
# ---------------------------------------------------------------------------
def _parse_versions(version_info: str) -> list[str]:
    """
    Parse the version_info field from OSM.
    Returns [] if all versions are affected, or a list of specific versions.
    """
    if not version_info:
        return []

    v = version_info.strip().lower()
    if v in ("all", "all versions", ""):
        return []
    if v.startswith("all versions") or v.startswith("all"):
        return []

    # Handle "X through Y" range patterns
    range_match = re.match(
        r"^(\d+\.\d+\.\d+)\s+through\s+(\d+\.\d+\.\d+)", version_info.strip()
    )
    if range_match:
        return _expand_version_range(range_match.group(1), range_match.group(2))

    # Strip trailing parenthetical notes
    cleaned = re.sub(r"\s*\(.*\)\s*$", "", version_info.strip())
    parts = [p.strip() for p in cleaned.split(",")]
    return [p for p in parts if re.match(r"^[v\d][\d.]*", p)]


def _expand_version_range(start: str, end: str) -> list[str]:
    try:
        s = [int(x) for x in start.split(".")]
        e = [int(x) for x in end.split(".")]
        if s[0] == e[0] and s[1] == e[1]:
            return [f"{s[0]}.{s[1]}.{p}" for p in range(s[2], e[2] + 1)]
    except (ValueError, IndexError):
        pass
    return [start, end]


# ---------------------------------------------------------------------------
# 3. Generate Rego policy
# ---------------------------------------------------------------------------
def blocklist_sets(items: list[dict]) -> tuple[set[str], set[tuple[str, str]]]:
    versioned: set[str] = set()
    wildcard: set[tuple[str, str]] = set()  # (format, name) for "all versions"
    for item in items:
        fmt, name, versions = item["format"], item["name"], item["versions"]
        if versions:
            for v in versions:
                versioned.add(f"{fmt}:{name}:{v}")
        else:
            wildcard.add((fmt, name))
    return versioned, wildcard


def count_entries(items: list[dict]) -> int:
    versioned, wildcard = blocklist_sets(items)
    return len(versioned) + len(wildcard)


def generate_rego(packages: list[dict], containers: list[dict]) -> str:
    versioned, wildcard = blocklist_sets(packages + containers)

    now = datetime.now(timezone.utc).isoformat()
    lines = [
        "package cloudsmith",
        "",
        "# ----------------------------------------------------------",
        "# Exact Blocklist - auto-synced from OpenSourceMalware.com",
        f"# Generated: {now}",
        f"# Packages:            {len(packages)}",
        f"# Container images:    {len(containers)}",
        f"# Versioned entries:   {len(versioned)}",
        f"# Wildcard entries:    {len(wildcard)}",
        f"# Severity: all levels (critical, high, medium, low)",
        "# ----------------------------------------------------------",
        "",
        "default match := false",
        "",
        "pkg := input.v0.package",
        "",
    ]

    # --- Versioned blocklist ---
    lines.append("blocklist := {")
    for i, entry in enumerate(sorted(versioned)):
        comma = "," if i < len(versioned) - 1 else ""
        lines.append(f'\t"{entry}"{comma}')
    lines.append("}")
    lines.append("")

    # --- Wildcard blocklist ---
    if wildcard:
        lines.append("# Packages and images blocked at ALL versions/tags")
        lines.append("blocklist_any_version := {")
        sorted_w = sorted(wildcard)
        for i, (fmt, name) in enumerate(sorted_w):
            comma = "," if i < len(sorted_w) - 1 else ""
            lines.append(f'\t"{fmt}:{name}"{comma}')
        lines.append("}")
        lines.append("")

    # --- Keys ---
    lines.append('pkg_key := sprintf("%s:%s:%s", [pkg.format, pkg.name, pkg.version])')
    lines.append("")

    # --- Match: exact version ---
    lines.append("match if {")
    lines.append("\tpkg.format != null")
    lines.append("\tpkg.name != null")
    lines.append("\tpkg.version != null")
    lines.append("\tpkg_key in blocklist")
    lines.append("}")
    lines.append("")

    # --- Match: wildcard ---
    if wildcard:
        lines.append('pkg_name_key := sprintf("%s:%s", [pkg.format, pkg.name])')
        lines.append("")
        lines.append("match if {")
        lines.append("\tpkg.format != null")
        lines.append("\tpkg.name != null")
        lines.append("\tpkg_name_key in blocklist_any_version")
        lines.append("}")
        lines.append("")

    # --- Reason messages ---
    lines.append("reason[msg] if {")
    lines.append("\tpkg_key in blocklist")
    lines.append("\tmsg := sprintf(")
    lines.append('\t\t"Blocked by explicit deny list: %s",')
    lines.append("\t\t[pkg_key],")
    lines.append("\t)")
    lines.append("}")
    lines.append("")

    if wildcard:
        lines.append("reason[msg] if {")
        lines.append("\tpkg_name_key in blocklist_any_version")
        lines.append("\tmsg := sprintf(")
        lines.append('\t\t"Blocked by wildcard deny list (all versions): %s",')
        lines.append("\t\t[pkg_name_key],")
        lines.append("\t)")
        lines.append("}")
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 4. Cloudsmith API
# ---------------------------------------------------------------------------
def _policy_url() -> str:
    return (
        f"{CLOUDSMITH_API_BASE}/workspaces/{CLOUDSMITH_WORKSPACE}"
        f"/policies/{CLOUDSMITH_POLICY_SLUG}/"
    )


def fetch_current_policy_rego() -> str:
    resp = requests.get(
        _policy_url(),
        headers={"X-Api-Key": CLOUDSMITH_API_KEY},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json().get("rego") or ""


def update_policy_rego(rego_code: str) -> dict:
    payload = {
        "rego": rego_code,
        "description": (
            f"Exact blocklist of malicious packages and container images "
            f"(all severities) from OpenSourceMalware.com. Auto-updated "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}."
        ),
    }
    resp = requests.patch(
        _policy_url(),
        json=payload,
        headers={"Content-Type": "application/json", "X-Api-Key": CLOUDSMITH_API_KEY},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# 5. Record store (state management)
# ---------------------------------------------------------------------------
def entry_id(item: dict) -> str:
    versions = item.get("versions", [])
    v = ",".join(versions) if versions else "*"
    return f"{item['type']}:{item['format']}:{item['name']}:{v}"


def load_store() -> tuple[dict[str, dict] | None, set[str]]:
    """
    Returns (records, legacy_entry_ids).
    records is None when no current-format store exists yet; legacy_entry_ids
    holds the old list-of-strings state if that's what's on disk.
    """
    if not os.path.exists(STATE_FILE):
        return None, set()
    with open(STATE_FILE) as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            log.warning(f"{STATE_FILE} is not valid JSON; ignoring it")
            return None, set()

    if isinstance(data, dict) and data.get("schema") == STORE_SCHEMA:
        return data.get("records", {}), set()
    if isinstance(data, list):
        return None, set(data)
    log.warning(f"{STATE_FILE} has an unrecognized shape; ignoring it")
    return None, set()


def save_store(records: dict[str, dict]):
    with open(STATE_FILE, "w") as f:
        json.dump(
            {
                "schema": STORE_SCHEMA,
                "updated": datetime.now(timezone.utc).isoformat(),
                "records": records,
            },
            f,
            indent=1,
            sort_keys=True,
        )


def _seed_record(rid: str, fmt: str, name: str, versions: list[str]) -> dict:
    return {
        "id": rid,
        "format": fmt,
        "name": name,
        "severity": "unknown",
        "versions": sorted(versions),
        "type": "container" if fmt == "docker" else "package",
        "osv_url": None,
        "last_updated": None,
        "legacy": True,
    }


def seed_from_rego(rego: str) -> dict[str, dict]:
    """Rebuild records from the blocklist sets in an existing generated policy."""
    versioned: dict[tuple[str, str], set[str]] = {}
    wildcard: set[tuple[str, str]] = set()

    section = None
    for line in rego.splitlines():
        s = line.strip()
        if s.startswith("blocklist := {"):
            section = "versioned"
            continue
        if s.startswith("blocklist_any_version := {"):
            section = "wildcard"
            continue
        if section and s.startswith("}"):
            section = None
            continue
        if not section:
            continue
        m = re.match(r'^"(.*)",?$', s)
        if not m:
            continue
        fmt, _, rest = m.group(1).partition(":")
        if section == "wildcard":
            wildcard.add((fmt, rest))
        else:
            name, _, ver = rest.rpartition(":")
            if name and ver:
                versioned.setdefault((fmt, name), set()).add(ver)

    records: dict[str, dict] = {}
    for fmt, name in wildcard:
        rid = f"seed:any:{fmt}:{name}"
        records[rid] = _seed_record(rid, fmt, name, [])
    for (fmt, name), vers in versioned.items():
        rid = f"seed:ver:{fmt}:{name}"
        records[rid] = _seed_record(rid, fmt, name, list(vers))
    return records


def seed_from_entry_ids(ids: set[str]) -> dict[str, dict]:
    """Rebuild records from the old list-of-entry-ids state file."""
    records: dict[str, dict] = {}
    for eid in ids:
        typ, _, rest = eid.partition(":")
        fmt, _, rest = rest.partition(":")
        name, _, v = rest.rpartition(":")
        if not name:
            continue
        rid = f"seed:{eid}"
        rec = _seed_record(rid, fmt, name, [] if v == "*" else v.split(","))
        rec["type"] = typ or rec["type"]
        records[rid] = rec
    return records


def merge_records(records: dict[str, dict], fresh: list[dict]) -> tuple[int, int]:
    """Upsert fresh OSM records by id. Returns (added, updated)."""
    added = updated = 0
    for item in fresh:
        existing = records.get(item["id"])
        if existing is None:
            added += 1
        elif existing != item:
            updated += 1
        records[item["id"]] = item
    return added, updated


# ---------------------------------------------------------------------------
# 6. OSV overlap tracking
# ---------------------------------------------------------------------------
def analyze_osv_overlap(packages: list[dict], containers: list[dict]) -> dict:
    """
    Analyze overlap between OSM and OSV databases. Records seeded from the
    previous policy carry no OSV metadata, so they're counted separately
    rather than skewing the percentages.
    """
    all_items = [i for i in packages + containers if not i.get("legacy")]
    legacy_count = len(packages) + len(containers) - len(all_items)

    in_both = [i for i in all_items if i.get("osv_url")]
    osm_only = [i for i in all_items if not i.get("osv_url")]

    pkg_in_both = [i for i in in_both if i["type"] == "package"]
    pkg_osm_only = [i for i in osm_only if i["type"] == "package"]
    ctr_in_both = [i for i in in_both if i["type"] == "container"]
    ctr_osm_only = [i for i in osm_only if i["type"] == "container"]

    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "totals": {
            "packages": len(packages),
            "containers": len(containers),
            "all": len(packages) + len(containers),
            "with_osm_metadata": len(all_items),
            "seeded_without_metadata": legacy_count,
        },
        "overlap": {
            "in_both_osm_and_osv": len(in_both),
            "osm_only": len(osm_only),
            "overlap_pct": round(len(in_both) / len(all_items) * 100, 1) if all_items else 0,
            "osm_exclusive_pct": round(len(osm_only) / len(all_items) * 100, 1) if all_items else 0,
        },
        "by_type": {
            "packages_in_both": len(pkg_in_both),
            "packages_osm_only": len(pkg_osm_only),
            "containers_in_both": len(ctr_in_both),
            "containers_osm_only": len(ctr_osm_only),
        },
        "osm_only_items": [
            {"format": i["format"], "name": i["name"], "type": i["type"]}
            for i in osm_only
        ],
        "osv_linked_items": [
            {"format": i["format"], "name": i["name"], "type": i["type"], "osv_url": i["osv_url"]}
            for i in in_both
        ],
    }


def log_overlap(overlap: dict):
    o = overlap["overlap"]
    t = overlap["by_type"]
    log.info("--- OSV Overlap Analysis ---")
    log.info(f"  Records with OSM metadata: {overlap['totals']['with_osm_metadata']} "
             f"(plus {overlap['totals']['seeded_without_metadata']} seeded from prior policy)")
    log.info(f"  In both OSM and OSV: {o['in_both_osm_and_osv']} ({o['overlap_pct']}%)")
    log.info(f"  OSM-only:            {o['osm_only']} ({o['osm_exclusive_pct']}%)")
    log.info(f"    Packages:  {t['packages_in_both']} in both, {t['packages_osm_only']} OSM-only")
    log.info(f"    Containers: {t['containers_in_both']} in both, {t['containers_osm_only']} OSM-only")


def save_overlap_report(overlap: dict):
    history = []
    if os.path.exists(OVERLAP_REPORT_FILE):
        with open(OVERLAP_REPORT_FILE) as f:
            try:
                history = json.load(f)
            except json.JSONDecodeError:
                history = []

    history.append(overlap)
    with open(OVERLAP_REPORT_FILE, "w") as f:
        json.dump(history, f, indent=2)
    log.info(f"  Overlap report saved ({len(history)} snapshots in {OVERLAP_REPORT_FILE})")


# ---------------------------------------------------------------------------
# 7. GitHub Actions summary
# ---------------------------------------------------------------------------
def write_summary(stats: dict, overlap: dict):
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if not summary_path:
        return
    o = overlap["overlap"]
    with open(summary_path, "a") as f:
        f.write("## OSM -> Cloudsmith Sync\n")
        f.write(f"- **Feed:** {OSM_FEED}\n")
        f.write(f"- **Fetched this run:** {stats['fetched']} "
                f"({stats['added']} new records, {stats['updated']} updated)\n")
        for s, c in sorted(stats["severity"].items()):
            f.write(f"  - {s}: {c}\n")
        f.write(f"- **Blocklist packages:** {stats['packages']}\n")
        f.write(f"- **Blocklist container images:** {stats['containers']}\n")
        f.write(f"- **Blocklist entries:** {stats['entries']}\n")
        f.write(f"- **Policy updated:** {'yes' if stats['policy_updated'] else 'no (no changes)'}\n")
        if stats["gaps"]:
            f.write(f"- :warning: **Possible gaps** (hit {QUERY_LATEST_LIMIT}-record cap): "
                    f"{', '.join(stats['gaps'])}\n")
        f.write(f"- **Run at:** {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write("### OSV Overlap (records with OSM metadata)\n")
        f.write("| Metric | Count | % |\n")
        f.write("|---|---|---|\n")
        f.write(f"| In both OSM & OSV | {o['in_both_osm_and_osv']} | {o['overlap_pct']}% |\n")
        f.write(f"| OSM-only | {o['osm_only']} | {o['osm_exclusive_pct']}% |\n")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    log.info("=== OpenSourceMalware -> Cloudsmith EPM Sync ===")
    log.info("    (packages + containers, all severities)")

    missing = [
        name for name, val in (
            ("OSM_API_KEY", OSM_API_KEY),
            ("CLOUDSMITH_API_KEY", CLOUDSMITH_API_KEY),
            ("CLOUDSMITH_WORKSPACE", CLOUDSMITH_WORKSPACE),
            ("CLOUDSMITH_POLICY_SLUG", CLOUDSMITH_POLICY_SLUG),
        ) if not val
    ]
    if missing:
        log.error(f"Missing required env vars: {', '.join(missing)}")
        sys.exit(1)
    if OSM_FEED not in ("query-latest", "threat-feed"):
        log.error(f"OSM_FEED must be 'query-latest' or 'threat-feed', got '{OSM_FEED}'")
        sys.exit(1)
    if not 1 <= OSM_LOOKBACK_HOURS <= 24:
        log.error("OSM_LOOKBACK_HOURS must be between 1 and 24")
        sys.exit(1)

    # Step 1: Load the record store, seeding it on first run
    records, legacy_ids = load_store()
    if records is None:
        log.info("No record store found; seeding from the current Cloudsmith policy "
                 "so existing blocks are preserved...")
        try:
            records = seed_from_rego(fetch_current_policy_rego())
            log.info(f"  Seeded {len(records)} records from live policy")
        except requests.RequestException as e:
            if legacy_ids:
                log.warning(f"  Couldn't read live policy ({e}); seeding from legacy {STATE_FILE}")
                records = seed_from_entry_ids(legacy_ids)
                log.info(f"  Seeded {len(records)} records from legacy state")
            else:
                log.error(f"  Couldn't read the live policy to seed from: {e}")
                log.error("  Aborting rather than risk overwriting the existing blocklist.")
                sys.exit(1)

    baseline = copy.deepcopy(records)

    # Step 2: Fetch from OSM
    try:
        fresh_packages, fresh_containers, gaps = fetch_osm_threats()
    except OSMError as e:
        log.error(str(e))
        sys.exit(1)
    fresh = fresh_packages + fresh_containers

    severity: dict[str, int] = {}
    for item in fresh:
        severity[item["severity"]] = severity.get(item["severity"], 0) + 1
    for s, c in sorted(severity.items()):
        log.info(f"  {s}: {c}")

    # Step 3: Merge into the store
    added, updated = merge_records(records, fresh)
    log.info(f"Store: {len(records)} records ({added} new, {updated} updated this run)")

    all_items = list(records.values())
    packages = [i for i in all_items if i["type"] != "container"]
    containers = [i for i in all_items if i["type"] == "container"]

    if not all_items:
        log.warning("No threats in store. Exiting without updating policy.")
        sys.exit(0)

    # Step 4: OSV overlap
    overlap = analyze_osv_overlap(packages, containers)
    log_overlap(overlap)
    save_overlap_report(overlap)

    stats = {
        "fetched": len(fresh),
        "added": added,
        "updated": updated,
        "severity": severity,
        "packages": len(packages),
        "containers": len(containers),
        "entries": count_entries(all_items),
        "policy_updated": False,
        "gaps": gaps,
    }

    # Step 5: Detect changes
    previous_ids = {entry_id(i) for i in baseline.values()}
    current_ids = {entry_id(i) for i in all_items}
    new = current_ids - previous_ids
    removed = previous_ids - current_ids

    if not new and not removed:
        log.info("No changes detected. Policy is up to date.")
        save_store(records)
        write_summary(stats, overlap)
        return

    log.info(f"Changes: +{len(new)} new, -{len(removed)} removed")
    for eid in sorted(new)[:20]:
        log.info(f"  NEW: {eid}")
    if len(new) > 20:
        log.info(f"  ... and {len(new) - 20} more")

    # Step 6: Safety check - never silently gut the blocklist
    prev_entries = count_entries(list(baseline.values()))
    new_entries = stats["entries"]
    if prev_entries and new_entries < prev_entries * (1 - MAX_SHRINK_PCT / 100):
        log.error(
            f"Blocklist would shrink from {prev_entries} to {new_entries} entries "
            f"(more than {MAX_SHRINK_PCT}%). Aborting without updating the policy. "
            "Raise MAX_SHRINK_PCT if this is expected."
        )
        sys.exit(1)

    # Step 7: Generate Rego and update Cloudsmith
    rego_code = generate_rego(packages, containers)
    log.info(f"Generated Rego ({len(rego_code)} chars, {new_entries} entries)")
    log.info(f"  {len(packages)} packages + {len(containers)} containers")

    log.info(f"Updating policy {CLOUDSMITH_POLICY_SLUG}...")
    try:
        result = update_policy_rego(rego_code)
        log.info(f"Policy updated: {result.get('name', 'OK')}")
    except requests.HTTPError as e:
        log.error(f"Failed to update policy: {e}")
        log.error(f"Response: {e.response.text if e.response is not None else 'N/A'}")
        sys.exit(1)

    # Step 8: Save state only after a successful update
    save_store(records)
    stats["policy_updated"] = True
    log.info("State saved. Done.")
    write_summary(stats, overlap)


if __name__ == "__main__":
    main()
