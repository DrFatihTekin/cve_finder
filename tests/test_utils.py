from datetime import datetime, timezone

import pytest

from cve_finder.utils import iso_date_to_nvd_range, parse_cvss, pick_english_description


def test_iso_date_to_nvd_range_date_only():
    start, end = iso_date_to_nvd_range("2024-01-01", "2024-01-02")
    assert start == "2024-01-01T00:00:00.000Z"
    assert end == "2024-01-02T00:00:00.000Z"


def test_iso_date_to_nvd_range_iso_with_timezone():
    start, end = iso_date_to_nvd_range("2024-01-01T12:30:00+00:00", None)
    assert start == "2024-01-01T12:30:00.000Z"
    # end is current time; just validate format
    assert end.endswith("Z") and "T" in end


def test_iso_date_to_nvd_range_iso_without_timezone():
    start, _ = iso_date_to_nvd_range("2024-01-01T12:30:00", "2024-01-01T13:00:00")
    assert start == "2024-01-01T12:30:00.000Z"


def test_iso_date_to_nvd_range_invalid():
    with pytest.raises(ValueError):
        iso_date_to_nvd_range("2024-13-01", None)


def test_pick_english_description():
    descriptions = [
        {"lang": "es", "value": "hola"},
        {"lang": "en", "value": "hello"},
    ]
    assert pick_english_description(descriptions) == "hello"


def test_pick_english_description_fallback_first():
    descriptions = [{"lang": "fr", "value": "salut"}]
    assert pick_english_description(descriptions) == "salut"


def test_pick_english_description_empty():
    assert pick_english_description([]) == ""


def test_parse_cvss_prefers_v31():
    metrics = {
        "cvssMetricV31": [{"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV30": [{"cvssData": {"baseScore": 9.0, "baseSeverity": "CRITICAL"}}],
        "cvssMetricV2": [{"cvssData": {"baseScore": 7.5}, "baseSeverity": "HIGH"}],
    }
    v31, v30, v2, sev = parse_cvss(metrics)
    assert (v31, v30, v2, sev) == (9.8, 9.0, 7.5, "CRITICAL")


def test_parse_cvss_v2_only():
    metrics = {"cvssMetricV2": [{"cvssData": {"baseScore": 5.0}, "baseSeverity": "MEDIUM"}]}
    v31, v30, v2, sev = parse_cvss(metrics)
    assert (v31, v30, v2, sev) == (None, None, 5.0, "MEDIUM")


def test_parse_cvss_v30_only():
    metrics = {"cvssMetricV30": [{"cvssData": {"baseScore": 6.1, "baseSeverity": "MEDIUM"}}]}
    v31, v30, v2, sev = parse_cvss(metrics)
    assert (v31, v30, v2, sev) == (None, 6.1, None, "MEDIUM")
