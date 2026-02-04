from cve_finder.models import CVEItem
from cve_finder.output import format_grouped


def test_grouped_output_includes_header():
    items = [
        CVEItem(
            cve_id="CVE-2024-0001",
            published="2024-01-01",
            last_modified=None,
            description="Test description",
            cvss_v31=9.8,
            cvss_v30=None,
            cvss_v2=None,
            severity="CRITICAL",
            references=["https://example.com"],
        )
    ]
    output = format_grouped(items)
    assert "CVE_ID | PUBLISHED | SCORE | DESCRIPTION" in output


def test_grouped_output_truncates_and_shows_more():
    items = [
        CVEItem(
            cve_id=f"CVE-2024-{i:04d}",
            published="2024-01-01",
            last_modified=None,
            description="Test description",
            cvss_v31=9.8,
            cvss_v30=None,
            cvss_v2=None,
            severity="CRITICAL",
            references=[],
        )
        for i in range(51)
    ]
    output = format_grouped(items)
    assert "... (1 more CRITICAL CVEs)" in output
