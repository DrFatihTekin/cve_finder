from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

import requests

from .models import CVEItem
from .utils import parse_cvss, pick_english_description


NVD_ENDPOINT = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_RESULTS_PER_PAGE = 200  # NVD allows up to 200 per request


def request_page(
    session: requests.Session,
    params: Dict[str, Any],
    api_key: Optional[str],
    timeout: int,
) -> Dict[str, Any]:
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
