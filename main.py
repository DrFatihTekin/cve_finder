#!/usr/bin/env python3
"""
Get CVEs per application from NVD (CVE API 2.0).

Usage examples:

1) Best (exact): use a CPE name
   python get_cves_per_app.py --cpe "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*" --csv nginx_1.24.0.csv

2) Keyword search (fuzzier):
   python get_cves_per_app.py --app "nginx" --version "1.24.0" --json out.json

3) Keyword search, no version:
   python get_cves_per_app.py --app "openssl" --since 2024-01-01 --max 200 --csv openssl.csv

Optional:
- Set an API key to reduce rate limiting:
  export NVD_API_KEY="your_key_here"
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import requests


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 200  # NVD allows up to 200 per request


@dataclass
class CVEItem:
    cve_id: str
    published: Optional[str]
    last_modified: Optional[str]
    description: str
    cvss_v31: Optional[float]
    cvss_v30: Optional[float]
    cvss_v2: Optional[float]
    severity: Optional[str]
    references: List[str]


def iso_date_to_nvd_range(since: str, until: Optional[str]) -> Tuple[str, str]:
    """
    Convert YYYY-MM-DD (or full ISO) into NVD required ISO-8601 with timezone.
    NVD expects e.g. 2024-01-01T00:00:00.000Z
    """
    def parse_date(d: str) -> datetime:
        # Accept YYYY-MM-DD or full ISO
        try:
            if len(d) == 10:
                return datetime.strptime(d, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            # try full ISO
            dt = datetime.fromisoformat(d.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception as e:
            raise ValueError(f"Invalid date format '{d}'. Use YYYY-MM-DD or ISO8601.") from e

    start_dt = parse_date(since)
    end_dt = parse_date(until) if until else datetime.now(timezone.utc)

    # NVD wants milliseconds and Z
    def fmt(dt: datetime) -> str:
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    return fmt(start_dt), fmt(end_dt)


def pick_english_description(descriptions: List[Dict[str, Any]]) -> str:
    for d in descriptions or []:
        if d.get("lang") == "en" and d.get("value"):
            return d["value"]
    # fallback: first description if exists
    if descriptions and descriptions[0].get("value"):
        return descriptions[0]["value"]
    return ""


def parse_cvss(metrics: Dict[str, Any]) -> Tuple[Optional[float], Optional[float], Optional[float], Optional[str]]:
    """
    Extract best available CVSS score and severity from NVD metrics.
    """
    v31 = v30 = v2 = None
    sev = None

    # CVSS v3.1
    m31 = metrics.get("cvssMetricV31") or []
    if m31:
        data = (m31[0].get("cvssData") or {})
        v31 = data.get("baseScore")
        sev = data.get("baseSeverity") or sev

    # CVSS v3.0
    m30 = metrics.get("cvssMetricV30") or []
    if m30:
        data = (m30[0].get("cvssData") or {})
        v30 = data.get("baseScore")
        sev = data.get("baseSeverity") or sev

    # CVSS v2
    m2 = metrics.get("cvssMetricV2") or []
    if m2:
        data = (m2[0].get("cvssData") or {})
        v2 = data.get("baseScore")
        # v2 severity sometimes under "baseSeverity" elsewhere; keep sev if already set
        sev = sev or m2[0].get("baseSeverity")

    return v31, v30, v2, sev


def build_params(args: argparse.Namespace) -> Dict[str, Any]:
    params: Dict[str, Any] = {
        "startIndex": 0,
        "resultsPerPage": args.page_size,
    }

    # Filter by application
    if args.cpe:
        params["cpeName"] = args.cpe
    else:
        # keywordSearch is broad; include version as additional keyword if provided
        keyword = args.app.strip()
        if args.version:
            keyword = f'{keyword} {args.version.strip()}'
        params["keywordSearch"] = keyword

    # Optional time window
    if args.since:
        start, end = iso_date_to_nvd_range(args.since, args.until)
        # Use "pubStartDate/pubEndDate" so you're filtering by published dates
        params["pubStartDate"] = start
        params["pubEndDate"] = end

    # Optional severity filtering (NVD supports cvssV3Severity)
    if args.severity:
        params["cvssV3Severity"] = args.severity.upper()

    return params


def request_page(session: requests.Session, params: Dict[str, Any], api_key: Optional[str], timeout: int) -> Dict[str, Any]:
    headers = {"User-Agent": "cve-per-app-script/1.0"}
    if api_key:
        headers["apiKey"] = api_key

    resp = session.get(NVD_ENDPOINT, params=params, headers=headers, timeout=timeout)
    if resp.status_code == 429:
        # Rate-limited. Back off and retry once.
        retry_after = resp.headers.get("Retry-After")
        sleep_s = int(retry_after) if retry_after and retry_after.isdigit() else 6
        time.sleep(sleep_s)
        resp = session.get(NVD_ENDPOINT, params=params, headers=headers, timeout=timeout)

    resp.raise_for_status()
    return resp.json()


def extract_items(nvd_json: Dict[str, Any]) -> List[CVEItem]:
    out: List[CVEItem] = []
    vulns = nvd_json.get("vulnerabilities") or []
    for v in vulns:
        c = (v.get("cve") or {})
        cve_id = c.get("id") or ""
        published = c.get("published")
        last_modified = c.get("lastModified")
        desc = pick_english_description(c.get("descriptions") or [])

        metrics = c.get("metrics") or {}
        v31, v30, v2, sev = parse_cvss(metrics)

        refs = []
        for r in (c.get("references") or []):
            url = r.get("url")
            if url:
                refs.append(url)

        out.append(
            CVEItem(
                cve_id=cve_id,
                published=published,
                last_modified=last_modified,
                description=desc,
                cvss_v31=v31,
                cvss_v30=v30,
                cvss_v2=v2,
                severity=sev,
                references=refs,
            )
        )
    return out


def save_json(items: List[CVEItem], path: str) -> None:
    data = [item.__dict__ for item in items]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def save_csv(items: List[CVEItem], path: str) -> None:
    fieldnames = [
        "cve_id",
        "published",
        "last_modified",
        "severity",
        "cvss_v31",
        "cvss_v30",
        "cvss_v2",
        "description",
        "references",
    ]
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for item in items:
            row = item.__dict__.copy()
            row["references"] = " | ".join(item.references)
            w.writerow(row)


def main() -> int:
    p = argparse.ArgumentParser(description="Fetch CVEs per application from NVD.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--cpe", help="Exact CPE name, e.g. cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*")
    group.add_argument("--app", help="Application name keyword, e.g. nginx, openssl, tomcat")

    p.add_argument("--version", help="Optional version (used only with --app keyword search)")
    p.add_argument("--since", help="Only CVEs published since date (YYYY-MM-DD or ISO8601)")
    p.add_argument("--until", help="End date for published window (YYYY-MM-DD or ISO8601). Default: now")

    p.add_argument("--severity", choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"], help="Filter by CVSS v3 severity")
    p.add_argument("--max", type=int, default=1000, help="Maximum CVEs to fetch (default 1000)")
    p.add_argument("--page-size", type=int, default=DEFAULT_RESULTS_PER_PAGE, help="Results per page (max 200)")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds")

    out_group = p.add_mutually_exclusive_group(required=False)
    out_group.add_argument("--json", dest="json_out", help="Write results to JSON file")
    out_group.add_argument("--csv", dest="csv_out", help="Write results to CSV file")
    
    p.add_argument("--format", choices=["json", "csv"], help="Output format to stdout (instead of grouped display)")

    args = p.parse_args()

    if args.page_size > 200 or args.page_size < 1:
        print("Error: --page-size must be between 1 and 200 for NVD.", file=sys.stderr)
        return 2

    api_key = os.getenv("NVD_API_KEY")  # optional but recommended
    params = build_params(args)

    items: List[CVEItem] = []
    session = requests.Session()

    fetched = 0
    total_results = None

    while True:
        page = request_page(session, params, api_key, args.timeout)
        if total_results is None:
            total_results = page.get("totalResults", 0)

        page_items = extract_items(page)
        items.extend(page_items)
        fetched += len(page_items)

        # Stop conditions
        if fetched >= args.max:
            items = items[: args.max]
            break

        start_index = params["startIndex"]
        results_per_page = params["resultsPerPage"]

        # If no more results
        if len(page_items) == 0:
            break

        # Next page
        next_index = start_index + results_per_page
        if total_results is not None and next_index >= total_results:
            break

        params["startIndex"] = next_index

        # Gentle pacing if no API key (avoid 429)
        if not api_key:
            time.sleep(0.8)

    # Sort by published date desc (if available)
    def sort_key(it: CVEItem):
        return it.published or ""

    items.sort(key=sort_key, reverse=True)

    # Output
    if args.json_out:
        save_json(items, args.json_out)
        print(f"Wrote {len(items)} CVEs to JSON: {args.json_out}")
    elif args.csv_out:
        save_csv(items, args.csv_out)
        print(f"Wrote {len(items)} CVEs to CSV: {args.csv_out}")
    elif args.format == "json":
        # Print JSON to stdout
        data = [item.__dict__ for item in items]
        print(json.dumps(data, ensure_ascii=False, indent=2))
    elif args.format == "csv":
        # Print CSV to stdout
        import io
        fieldnames = ["cve_id", "published", "last_modified", "severity", "cvss_v31", "cvss_v30", "cvss_v2", "description", "references"]
        output = io.StringIO()
        w = csv.DictWriter(output, fieldnames=fieldnames)
        w.writeheader()
        for item in items:
            row = item.__dict__.copy()
            row["references"] = " | ".join(item.references)
            w.writerow(row)
        print(output.getvalue())
    else:
        # Group by severity
        from collections import defaultdict
        by_severity = defaultdict(list)
        for it in items:
            sev = it.severity or "UNKNOWN"
            by_severity[sev].append(it)
        
        # Print grouped by severity (CRITICAL -> HIGH -> MEDIUM -> LOW -> UNKNOWN)
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        total_printed = 0
        for sev in severity_order:
            if sev not in by_severity:
                continue
            cves = by_severity[sev]
            print(f"\n{'='*80}")
            print(f"{sev} ({len(cves)} CVEs)")
            print(f"{'='*80}")
            for it in cves[:50]:  # Limit per severity group
                score = it.cvss_v31 or it.cvss_v30 or it.cvss_v2
                print(f"{it.cve_id} | {it.published} | {score} | {it.description[:100]}")
                total_printed += 1
            if len(cves) > 50:
                print(f"... ({len(cves) - 50} more {sev} CVEs)")
        
        print(f"\nTotal CVEs fetched: {len(items)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
