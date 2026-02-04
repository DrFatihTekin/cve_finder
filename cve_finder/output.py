from __future__ import annotations

import csv
import json
from typing import List

from .models import CVEItem


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


def format_json(items: List[CVEItem]) -> str:
    data = [item.__dict__ for item in items]
    return json.dumps(data, ensure_ascii=False, indent=2)


def format_csv(items: List[CVEItem]) -> str:
    import io

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
    output = io.StringIO()
    w = csv.DictWriter(output, fieldnames=fieldnames)
    w.writeheader()
    for item in items:
        row = item.__dict__.copy()
        row["references"] = " | ".join(item.references)
        w.writerow(row)
    return output.getvalue()


def format_grouped(items: List[CVEItem]) -> str:
    from collections import defaultdict

    by_severity = defaultdict(list)
    for it in items:
        sev = it.severity or "UNKNOWN"
        by_severity[sev].append(it)

    # Print grouped by severity (CRITICAL -> HIGH -> MEDIUM -> LOW -> UNKNOWN)
    severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    lines = []
    total_printed = 0
    header = "CVE_ID | PUBLISHED | SCORE | DESCRIPTION"
    for sev in severity_order:
        if sev not in by_severity:
            continue
        cves = by_severity[sev]
        lines.append(f"\n{'='*80}")
        lines.append(f"{sev} ({len(cves)} CVEs)")
        lines.append(f"{'='*80}")
        lines.append(header)
        for it in cves[:50]:  # Limit per severity group
            score = it.cvss_v31 or it.cvss_v30 or it.cvss_v2
            lines.append(f"{it.cve_id} | {it.published} | {score} | {it.description[:100]}")
            total_printed += 1
        if len(cves) > 50:
            lines.append(f"... ({len(cves) - 50} more {sev} CVEs)")

    lines.append(f"\nTotal CVEs fetched: {len(items)}")
    return "\n".join(lines)
