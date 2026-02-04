from cve_finder.models import CVEItem
from cve_finder.output import format_csv, format_json


def make_item() -> CVEItem:
    return CVEItem(
        cve_id="CVE-2024-0002",
        published="2024-01-03",
        last_modified=None,
        description="Example",
        cvss_v31=None,
        cvss_v30=7.2,
        cvss_v2=None,
        severity="HIGH",
        references=["https://example.com", "https://example.org"],
    )


def test_format_json_contains_id():
    output = format_json([make_item()])
    assert "CVE-2024-0002" in output


def test_format_csv_has_header_and_refs():
    output = format_csv([make_item()])
    lines = output.strip().splitlines()
    assert lines[0].startswith("cve_id,published,last_modified")
    assert "https://example.com | https://example.org" in output
