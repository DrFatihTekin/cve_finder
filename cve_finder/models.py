from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


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
