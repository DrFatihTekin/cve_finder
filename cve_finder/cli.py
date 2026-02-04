from __future__ import annotations

import argparse
import os
import sys
import time
from typing import Any, Dict, List

import requests

from .api import DEFAULT_RESULTS_PER_PAGE, extract_items, request_page
from .models import CVEItem
from .output import format_csv, format_grouped, format_json, save_csv, save_json
from .utils import iso_date_to_nvd_range


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Fetch CVEs per application from NVD.")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--cpe", help="Exact CPE name, e.g. cpe:2.3:a:vendor:product:version:*:*:*:*:*:*:*")
    group.add_argument("--app", help="Application name keyword, e.g. nginx, openssl, tomcat")

    p.add_argument("--version", help="Optional version (used only with --app keyword search)")
    p.add_argument("--since", help="Only CVEs published since date (YYYY-MM-DD or ISO8601)")
    p.add_argument("--until", help="End date for published window (YYYY-MM-DD or ISO8601). Default: now")

    p.add_argument(
        "--severity",
        action="append",
        help="Filter by CVSS v3 severity. Use multiple --severity flags or a comma-separated list (e.g., CRITICAL,MEDIUM).",
    )
    p.add_argument("--max", type=int, default=1000, help="Maximum CVEs to fetch (default 1000)")
    p.add_argument("--page-size", type=int, default=DEFAULT_RESULTS_PER_PAGE, help="Results per page (max 200)")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds")

    out_group = p.add_mutually_exclusive_group(required=False)
    out_group.add_argument("--json", dest="json_out", help="Write results to JSON file")
    out_group.add_argument("--csv", dest="csv_out", help="Write results to CSV file")

    p.add_argument("--format", choices=["json", "csv"], help="Output format to stdout (instead of grouped display)")
    return p


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
            keyword = f"{keyword} {args.version.strip()}"
        params["keywordSearch"] = keyword

    # Optional time window
    if args.since:
        start, end = iso_date_to_nvd_range(args.since, args.until)
        # Use "pubStartDate/pubEndDate" so you're filtering by published dates
        params["pubStartDate"] = start
        params["pubEndDate"] = end

    # Optional severity filtering (NVD supports single cvssV3Severity)
    severities = normalize_severities(args.severity)
    if len(severities) == 1:
        params["cvssV3Severity"] = severities[0]

    return params


def fetch_cves(args: argparse.Namespace) -> List[CVEItem]:
    if args.page_size > 200 or args.page_size < 1:
        raise ValueError("--page-size must be between 1 and 200 for NVD.")

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

    # Local severity filter in case API doesn't enforce it reliably
    severities = normalize_severities(args.severity)
    if severities:
        items = [it for it in items if (it.severity or "").upper() in severities]

    # Sort by published date desc (if available)
    items.sort(key=lambda it: it.published or "", reverse=True)
    return items


def normalize_severities(raw: List[str] | None) -> List[str]:
    if not raw:
        return []
    allowed = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    values = []
    for entry in raw:
        parts = [p.strip().upper() for p in entry.split(",") if p.strip()]
        values.extend(parts)
    invalid = [v for v in values if v not in allowed]
    if invalid:
        raise ValueError(f"Invalid severity value(s): {', '.join(invalid)}")
    # Preserve order and uniqueness
    seen = set()
    result = []
    for v in values:
        if v not in seen:
            seen.add(v)
            result.append(v)
    return result


def output_results(items: List[CVEItem], args: argparse.Namespace) -> int:
    if args.json_out:
        save_json(items, args.json_out)
        print(f"Wrote {len(items)} CVEs to JSON: {args.json_out}")
    elif args.csv_out:
        save_csv(items, args.csv_out)
        print(f"Wrote {len(items)} CVEs to CSV: {args.csv_out}")
    elif args.format == "json":
        print(format_json(items))
    elif args.format == "csv":
        print(format_csv(items))
    else:
        print(format_grouped(items))

    return 0


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        items = fetch_cves(args)
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2

    return output_results(items, args)
