from types import SimpleNamespace

from cve_finder.cli import output_results
from cve_finder.models import CVEItem


def make_item() -> CVEItem:
    return CVEItem(
        cve_id="CVE-2024-1234",
        published="2024-01-01",
        last_modified=None,
        description="Example",
        cvss_v31=9.0,
        cvss_v30=None,
        cvss_v2=None,
        severity="CRITICAL",
        references=[],
    )


def test_output_results_grouped(capsys):
    args = SimpleNamespace(json_out=None, csv_out=None, format=None)
    output_results([make_item()], args)
    assert "Total CVEs fetched" in capsys.readouterr().out


def test_output_results_json_format(capsys):
    args = SimpleNamespace(json_out=None, csv_out=None, format="json")
    output_results([make_item()], args)
    assert "CVE-2024-1234" in capsys.readouterr().out


def test_output_results_csv_format(capsys):
    args = SimpleNamespace(json_out=None, csv_out=None, format="csv")
    output_results([make_item()], args)
    out = capsys.readouterr().out
    assert out.startswith("cve_id,published,last_modified")


def test_output_results_json_file(tmp_path, capsys):
    path = tmp_path / "out.json"
    args = SimpleNamespace(json_out=str(path), csv_out=None, format=None)
    output_results([make_item()], args)
    assert path.exists()
    assert "Wrote 1 CVEs to JSON" in capsys.readouterr().out


def test_output_results_csv_file(tmp_path, capsys):
    path = tmp_path / "out.csv"
    args = SimpleNamespace(json_out=None, csv_out=str(path), format=None)
    output_results([make_item()], args)
    assert path.exists()
    assert "Wrote 1 CVEs to CSV" in capsys.readouterr().out
