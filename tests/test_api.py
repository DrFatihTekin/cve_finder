from cve_finder.api import extract_items


def test_extract_items_minimal():
    sample = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "published": "2024-01-01",
                    "lastModified": "2024-01-02",
                    "descriptions": [{"lang": "en", "value": "Test"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}}
                        ]
                    },
                    "references": [{"url": "https://example.com"}],
                }
            }
        ]
    }

    items = extract_items(sample)
    assert len(items) == 1
    item = items[0]
    assert item.cve_id == "CVE-2024-0001"
    assert item.published == "2024-01-01"
    assert item.last_modified == "2024-01-02"
    assert item.description == "Test"
    assert item.cvss_v31 == 9.8
    assert item.severity == "CRITICAL"
    assert item.references == ["https://example.com"]
