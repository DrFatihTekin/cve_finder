from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple


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
