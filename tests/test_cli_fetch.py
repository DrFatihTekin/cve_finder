from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cve_finder import cli
from cve_finder.models import CVEItem


def make_item(sev: str, published: str = "2024-01-01") -> CVEItem:
    return CVEItem(
        cve_id="CVE-2024-0001",
        published=published,
        last_modified=None,
        description="Test",
        cvss_v31=9.8 if sev == "CRITICAL" else None,
        cvss_v30=None,
        cvss_v2=None,
        severity=sev,
        references=[],
    )


def test_fetch_cves_paginates_and_filters(monkeypatch):
    args = SimpleNamespace(
        page_size=1,
        max=2,
        timeout=1,
        cpe=None,
        app="jira",
        version=None,
        since=None,
        until=None,
        severity=["critical"],
    )

    pages = [
        {"totalResults": 2, "vulnerabilities": ["page1"]},
        {"totalResults": 2, "vulnerabilities": ["page2"]},
    ]
    req_mock = Mock(side_effect=pages)
    monkeypatch.setattr(cli, "request_page", req_mock)

    def extract_stub(page):
        if page["vulnerabilities"] == ["page1"]:
            return [make_item("CRITICAL", "2024-02-01")]
        return [make_item("MEDIUM", "2024-01-01")]

    monkeypatch.setattr(cli, "extract_items", extract_stub)

    items = cli.fetch_cves(args)
    assert len(items) == 1
    assert items[0].severity == "CRITICAL"
    assert items[0].published == "2024-02-01"
    assert req_mock.call_count == 2


def test_fetch_cves_invalid_page_size():
    args = SimpleNamespace(
        page_size=500,
        max=1,
        timeout=1,
        cpe="cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*",
        app=None,
        version=None,
        since=None,
        until=None,
        severity=None,
    )
    with pytest.raises(ValueError):
        cli.fetch_cves(args)


def test_fetch_cves_breaks_on_no_results(monkeypatch):
    args = SimpleNamespace(
        page_size=10,
        max=100,
        timeout=1,
        cpe=None,
        app="jira",
        version=None,
        since=None,
        until=None,
        severity=None,
    )

    monkeypatch.setenv("NVD_API_KEY", "x")
    monkeypatch.setattr(cli, "request_page", Mock(return_value={"totalResults": 0, "vulnerabilities": []}))
    monkeypatch.setattr(cli, "extract_items", lambda _page: [])

    items = cli.fetch_cves(args)
    assert items == []


def test_fetch_cves_stops_when_total_reached(monkeypatch):
    args = SimpleNamespace(
        page_size=1,
        max=100,
        timeout=1,
        cpe=None,
        app="jira",
        version=None,
        since=None,
        until=None,
        severity=None,
    )

    monkeypatch.setenv("NVD_API_KEY", "x")
    req_mock = Mock(return_value={"totalResults": 1, "vulnerabilities": ["page1"]})
    monkeypatch.setattr(cli, "request_page", req_mock)
    monkeypatch.setattr(cli, "extract_items", lambda _page: [make_item("HIGH")])

    items = cli.fetch_cves(args)
    assert len(items) == 1
    assert req_mock.call_count == 1


def test_fetch_cves_sleeps_without_api_key(monkeypatch):
    args = SimpleNamespace(
        page_size=1,
        max=100,
        timeout=1,
        cpe=None,
        app="jira",
        version=None,
        since=None,
        until=None,
        severity=None,
    )

    monkeypatch.delenv("NVD_API_KEY", raising=False)
    pages = [
        {"totalResults": 2, "vulnerabilities": ["page1"]},
        {"totalResults": 2, "vulnerabilities": ["page2"]},
    ]
    req_mock = Mock(side_effect=pages)
    monkeypatch.setattr(cli, "request_page", req_mock)
    monkeypatch.setattr(cli, "extract_items", lambda _page: [make_item("LOW")])

    sleep_mock = Mock()
    monkeypatch.setattr(cli.time, "sleep", sleep_mock)

    cli.fetch_cves(args)
    assert sleep_mock.call_count == 1
