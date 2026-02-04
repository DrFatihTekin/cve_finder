from cve_finder.models import CVEItem
from cve_finder.output import save_csv, save_json


def make_item() -> CVEItem:
    return CVEItem(
        cve_id="CVE-2024-9999",
        published="2024-01-01",
        last_modified="2024-01-02",
        description="Example",
        cvss_v31=7.5,
        cvss_v30=None,
        cvss_v2=None,
        severity="HIGH",
        references=["https://example.com"],
    )


def test_save_json(tmp_path):
    path = tmp_path / "out.json"
    save_json([make_item()], str(path))
    content = path.read_text(encoding="utf-8")
    assert "CVE-2024-9999" in content


def test_save_csv(tmp_path):
    path = tmp_path / "out.csv"
    save_csv([make_item()], str(path))
    content = path.read_text(encoding="utf-8")
    assert content.splitlines()[0].startswith("cve_id,published,last_modified")
    assert "CVE-2024-9999" in content
