from types import SimpleNamespace

from cve_finder import cli


def test_main_success(monkeypatch, capsys):
    args = SimpleNamespace()
    monkeypatch.setattr(cli, "build_parser", lambda: SimpleNamespace(parse_args=lambda: args))
    monkeypatch.setattr(cli, "fetch_cves", lambda _args: [])
    monkeypatch.setattr(cli, "output_results", lambda items, _args: 0)

    assert cli.main() == 0
    captured = capsys.readouterr()
    assert captured.err == ""


def test_main_error(monkeypatch, capsys):
    args = SimpleNamespace()
    monkeypatch.setattr(cli, "build_parser", lambda: SimpleNamespace(parse_args=lambda: args))
    monkeypatch.setattr(cli, "fetch_cves", lambda _args: (_ for _ in ()).throw(ValueError("bad")))

    assert cli.main() == 2
    captured = capsys.readouterr()
    assert "Error: bad" in captured.err
