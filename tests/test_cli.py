import pytest

from cve_finder.cli import build_params, build_parser, normalize_severities


class DummyArgs:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


def test_normalize_severities_single_case_insensitive():
    assert normalize_severities(["critical"]) == ["CRITICAL"]


def test_normalize_severities_comma_separated():
    assert normalize_severities(["CRITICAl,medium"]) == ["CRITICAL", "MEDIUM"]


def test_normalize_severities_multiple_flags_with_duplicates():
    assert normalize_severities(["high", "HIGH", "medium"]) == ["HIGH", "MEDIUM"]


def test_normalize_severities_invalid_value():
    with pytest.raises(ValueError):
        normalize_severities(["low,unknown"])


def test_build_params_with_cpe_and_severity():
    args = DummyArgs(
        cpe="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        app=None,
        version=None,
        since=None,
        until=None,
        severity=["critical"],
        page_size=100,
    )
    params = build_params(args)
    assert params["cpeName"].startswith("cpe:2.3:a:")
    assert params["cvssV3Severity"] == "CRITICAL"


def test_build_params_with_app_and_version_and_dates():
    args = DummyArgs(
        cpe=None,
        app="nginx",
        version="1.24.0",
        since="2024-01-01",
        until="2024-01-02",
        severity=None,
        page_size=50,
    )
    params = build_params(args)
    assert params["keywordSearch"] == "nginx 1.24.0"
    assert params["pubStartDate"].endswith("Z")
    assert params["pubEndDate"].endswith("Z")


def test_build_parser_parses_args():
    parser = build_parser()
    args = parser.parse_args(["--app", "nginx", "--severity", "low", "--format", "json"])
    assert args.app == "nginx"
    assert args.severity == ["low"]
    assert args.format == "json"
