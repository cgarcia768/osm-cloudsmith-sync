#!/usr/bin/env python3
"""
Sync malicious packages AND container images (ALL severity levels) from
OpenSourceMalware.com into a Cloudsmith EPM "Exact Blocklist" Rego policy.

Designed to run as a GitHub Actions scheduled workflow (hourly).

Environment variables required:
  CLOUDSMITH_API_KEY       - Your Cloudsmith API key
  CLOUDSMITH_WORKSPACE     - Your Cloudsmith workspace slug
  CLOUDSMITH_POLICY_SLUG   - The slug_perm of your "Exact Blocklist" EPM policy
"""

import os
import sys
import json
import logging
import re
from datetime import datetime, timezone

import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
OSM_FEED_URL = "https://zyqmpfcrijqmwyzbkubf.supabase.co/functions/v1/query-public-feed"
OSM_SEARCH_URL = "https://zyqmpfcrijqmwyzbkubf.supabase.co/functions/v1/query-search"
OSM_API_KEY = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inp5cW1wZmNyaWpxbXd5emJrdWJmIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTY0NTk3OTEsImV4cCI6MjA3MjAzNTc5MX0."
    "yWPKxflym3oo0Dpw8U-wMzViP8xgGHUY5sluMbK0SoU"
)

CLOUDSMITH_API_BASE = "https://api.cloudsmith.io/v2"
CLOUDSMITH_API_KEY = os.environ.get("CLOUDSMITH_API_KEY", "")
CLOUDSMITH_WORKSPACE = os.environ.get("CLOUDSMITH_WORKSPACE", "")
CLOUDSMITH_POLICY_SLUG = os.environ.get("CLOUDSMITH_POLICY_SLUG", "")

STATE_FILE = os.environ.get("STATE_FILE", "last_known_packages.json")

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)

REGISTRY_TO_FORMAT = {
    "npm": "npm",
    "pypi": "python",
    "maven": "maven",
    "nuget": "nuget",
    "rubygems": "ruby",
    "go": "go",
    "cargo": "cargo",
    "packagist": "php",
    "hex": "hex",
    "cocoapods": "cocoapods",
    "pub": "dart",
    "dockerhub": "docker",
}


def _osm_headers() -> dict:
    return {
        "Content-Type": "application/json",
        "apikey": OSM_API_KEY,
        "Authorization": f"Bearer {OSM_API_KEY}",
    }


# ---------------------------------------------------------------------------
# 1. Fetch malicious packages from OSM (packages feed)
# ---------------------------------------------------------------------------
def fetch_malicious_packages() -> list[dict]:
    """Fetch all package-type threats via the public feed endpoint."""
    payload = {"includeModified": False}
    log.info("Fetching packages from OSM API...")
    resp = requests.post(OSM_FEED_URL, json=payload, headers=_osm_headers(), timeout=60)
    resp.raise_for_status()
    data = resp.json()
    threats = data.get("threats", [])
    log.info(f"  Packages feed returned {len(threats)} total threats")

    packages = []
    for t in threats:
        if t.get("report_type") != "package":
            continue

        name = t.get("package_name") or ""
        registry = t.get("registry") or ""
        if not name or not registry:
            continue

        fmt = REGISTRY_TO_FORMAT.get(registry.lower(), registry.lower())
        packages.append({
            "format": fmt,
            "name": name,
            "severity": t.get("severity_level", "unknown"),
            "versions": _parse_versions(t.get("version_info") or ""),
            "type": "package",
        })

    log.info(f"  Filtered to {len(packages)} package entries")
    return packages


# ---------------------------------------------------------------------------
# 2. Fetch malicious container images from OSM (search endpoint)
# ---------------------------------------------------------------------------
def fetch_malicious_containers() -> list[dict]:
    """Fetch all container-type threats via the search endpoint."""
    payload = {
        "searchType": "type",
        "typeFilter": "container",
        "severityFilter": "",
        "isAdmin": False,
    }
    log.info("Fetching containers from OSM API...")
    resp = requests.post(OSM_SEARCH_URL, json=payload, headers=_osm_headers(), timeout=60)
    resp.raise_for_status()
    data = resp.json()
    threats = data.get("data", [])
    log.info(f"  Container feed returned {len(threats)} threats")

    containers = []
    for t in threats:
        image_name = t.get("package_name") or t.get("resource_identifier") or ""
        if not image_name:
            continue

        fmt = REGISTRY_TO_FORMAT.get(
            (t.get("registry") or "docker").lower(), "docker"
        )
        containers.append({
            "format": fmt,
            "name": image_name,
            "severity": t.get("severity_level", "unknown"),
            "versions": _parse_versions(t.get("version_info") or ""),
            "type": "container",
        })

    log.info(f"  Filtered to {len(containers)} container entries")
    return containers


# ---------------------------------------------------------------------------
# 3. Version parsing
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
# 4. Generate Rego policy
# ---------------------------------------------------------------------------
def generate_rego(packages: list[dict], containers: list[dict]) -> str:
    versioned = set()
    wildcard = set()  # (format, name) for "all versions"

    for item in packages + containers:
        fmt, name, versions = item["format"], item["name"], item["versions"]
        if versions:
            for v in versions:
                versioned.add(f"{fmt}:{name}:{v}")
        else:
            wildcard.add((fmt, name))

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
# 5. Cloudsmith API
# ---------------------------------------------------------------------------
def update_policy_rego(rego_code: str) -> dict:
    url = (
        f"{CLOUDSMITH_API_BASE}/workspaces/{CLOUDSMITH_WORKSPACE}"
        f"/policies/{CLOUDSMITH_POLICY_SLUG}/"
    )
    payload = {
        "rego": rego_code,
        "description": (
            f"Exact blocklist of malicious packages and container images "
            f"(all severities) from OpenSourceMalware.com. Auto-updated "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}."
        ),
    }
    resp = requests.patch(
        url,
        json=payload,
        headers={"Content-Type": "application/json", "X-Api-Key": CLOUDSMITH_API_KEY},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()


# ---------------------------------------------------------------------------
# 6. State management
# ---------------------------------------------------------------------------
def load_state() -> set[str]:
    if os.path.exists(STATE_FILE):
        with open(STATE_FILE) as f:
            return set(json.load(f))
    return set()


def save_state(ids: set[str]):
    with open(STATE_FILE, "w") as f:
        json.dump(sorted(ids), f)


def entry_id(item: dict) -> str:
    versions = item.get("versions", [])
    v = ",".join(versions) if versions else "*"
    return f"{item['type']}:{item['format']}:{item['name']}:{v}"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    log.info("=== OpenSourceMalware -> Cloudsmith EPM Sync ===")
    log.info("    (packages + containers, all severities)")

    missing = []
    if not CLOUDSMITH_API_KEY:
        missing.append("CLOUDSMITH_API_KEY")
    if not CLOUDSMITH_WORKSPACE:
        missing.append("CLOUDSMITH_WORKSPACE")
    if not CLOUDSMITH_POLICY_SLUG:
        missing.append("CLOUDSMITH_POLICY_SLUG")
    if missing:
        log.error(f"Missing required env vars: {', '.join(missing)}")
        sys.exit(1)

    # Step 1: Fetch both feeds (separate endpoints)
    packages = fetch_malicious_packages()
    containers = fetch_malicious_containers()
    all_items = packages + containers

    # Severity breakdown
    sev: dict[str, int] = {}
    for item in all_items:
        sev[item["severity"]] = sev.get(item["severity"], 0) + 1
    for s, c in sorted(sev.items()):
        log.info(f"  {s}: {c}")

    if not all_items:
        log.warning("No threats found. Exiting without updating policy.")
        sys.exit(0)

    # Step 2: Check for changes
    current_ids = {entry_id(i) for i in all_items}
    previous_ids = load_state()
    new = current_ids - previous_ids
    removed = previous_ids - current_ids

    if not new and not removed:
        log.info("No changes detected. Policy is up to date.")
        return

    log.info(f"Changes: +{len(new)} new, -{len(removed)} removed")
    for eid in sorted(new)[:20]:
        log.info(f"  NEW: {eid}")
    if len(new) > 20:
        log.info(f"  ... and {len(new) - 20} more")

    # Step 3: Generate Rego
    rego_code = generate_rego(packages, containers)
    log.info(f"Generated Rego ({len(rego_code)} chars)")
    log.info(f"  {len(packages)} packages + {len(containers)} containers")

    # Step 4: Update Cloudsmith
    log.info(f"Updating policy {CLOUDSMITH_POLICY_SLUG}...")
    try:
        result = update_policy_rego(rego_code)
        log.info(f"Policy updated: {result.get('name', 'OK')}")
    except requests.HTTPError as e:
        log.error(f"Failed to update policy: {e}")
        log.error(f"Response: {e.response.text if e.response else 'N/A'}")
        sys.exit(1)

    # Step 5: Save state
    save_state(current_ids)
    log.info("State saved. Done.")

    # GitHub Actions summary
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
    if summary_path:
        with open(summary_path, "a") as f:
            f.write("## OSM -> Cloudsmith Sync\n")
            f.write(f"- **Packages:** {len(packages)}\n")
            f.write(f"- **Container images:** {len(containers)}\n")
            for s, c in sorted(sev.items()):
                f.write(f"  - {s}: {c}\n")
            f.write(f"- **New:** {len(new)}\n")
            f.write(f"- **Removed:** {len(removed)}\n")
            f.write(f"- **Updated:** {datetime.now(timezone.utc).isoformat()}\n")


if __name__ == "__main__":
    main()
