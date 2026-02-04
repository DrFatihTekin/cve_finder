from unittest.mock import Mock

import pytest

from cve_finder.api import request_page


class DummyResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise RuntimeError("http error")

    def json(self):
        return self._json_data


def test_request_page_retries_on_429(monkeypatch):
    session = Mock()
    session.get.side_effect = [
        DummyResponse(429, headers={"Retry-After": "0"}),
        DummyResponse(200, json_data={"ok": True}),
    ]

    monkeypatch.setattr("time.sleep", lambda *_: None)

    result = request_page(session, {"a": 1}, api_key=None, timeout=1)
    assert result == {"ok": True}
    assert session.get.call_count == 2


def test_request_page_includes_api_key_header():
    session = Mock()
    session.get.return_value = DummyResponse(200, json_data={"ok": True})

    request_page(session, {"a": 1}, api_key="key", timeout=1)
    _, kwargs = session.get.call_args
    assert kwargs["headers"]["apiKey"] == "key"


def test_request_page_raises_on_error():
    session = Mock()
    session.get.return_value = DummyResponse(500)

    with pytest.raises(RuntimeError):
        request_page(session, {"a": 1}, api_key=None, timeout=1)
