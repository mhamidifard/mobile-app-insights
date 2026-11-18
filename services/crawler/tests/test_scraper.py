from datetime import UTC, datetime
from unittest.mock import Mock, call
from urllib.error import HTTPError, URLError

import pytest
from configs import BASE_BACKOFF, FALLBACK_VERSION_LABEL, MAX_BACKOFF
from google_play_scraper.exceptions import ExtraHTTPError, NotFoundError
from models import AppMetrics
from scraper import PlayStoreScraper

PACKAGE = "org.telegram.messenger"
OBSERVED_AT = datetime(2026, 11, 18, 12, tzinfo=UTC)


@pytest.fixture
def delays(monkeypatch):
    recorded = []
    monkeypatch.setattr("scraper.time.sleep", recorded.append)
    return recorded


@pytest.mark.parametrize(
    "payload",
    [{"score": 4.567}, {"ratings": 0}, {"adSupported": False}, {"version": "1.2"}, {"title": "Telegram"}],
)
def test_returns_metrics_from_a_partial_listing(payload, monkeypatch, delays):
    fetch = Mock(return_value=payload)
    clock = Mock()
    clock.now.return_value = OBSERVED_AT
    monkeypatch.setattr("scraper.datetime", clock)

    result = PlayStoreScraper(fetch_app_details=fetch).get_app_metrics(PACKAGE)

    fetch.assert_called_once_with(PACKAGE, lang="en", country="us")
    clock.now.assert_called_once_with(UTC)
    assert result == AppMetrics.from_scraped_payload(payload, OBSERVED_AT.isoformat())
    assert delays == []


@pytest.mark.parametrize(
    "outcome",
    [
        NotFoundError("not found"), None, [], {},
        {"appId": PACKAGE, "url": "https://example.invalid", "title": " ", "score": None, "version": FALLBACK_VERSION_LABEL},
    ],
)
def test_skips_unavailable_or_unusable_listing(outcome, delays, caplog):
    fetch = Mock(side_effect=[outcome])

    assert PlayStoreScraper(fetch_app_details=fetch).get_app_metrics(PACKAGE) is None
    fetch.assert_called_once_with(PACKAGE, lang="en", country="us")
    assert delays == []
    assert PACKAGE in caplog.text


def wrapped_http_error(status: int) -> ExtraHTTPError:
    error = ExtraHTTPError(f"App not found. Status code {status} returned.")
    error.__context__ = HTTPError("https://example.invalid", status, "request failed", {}, None)
    return error


@pytest.mark.parametrize(
    "error",
    [
        wrapped_http_error(408), wrapped_http_error(429), wrapped_http_error(503),
        TimeoutError("timeout"), URLError("connection refused"), ConnectionResetError("reset"),
    ],
)
def test_retries_transient_failure_then_returns_metrics(error, delays):
    fetch = Mock(side_effect=[error, {"ratings": 7}])

    result = PlayStoreScraper(fetch_app_details=fetch).get_app_metrics(PACKAGE)

    assert result.ratings == 7
    assert fetch.call_args_list == [call(PACKAGE, lang="en", country="us")] * 2
    assert delays == [min(BASE_BACKOFF, MAX_BACKOFF)]


def test_caps_backoff_and_stops_after_five_failed_fetches(delays, caplog):
    fetch = Mock(side_effect=TimeoutError("read timed out"))
    scraper = PlayStoreScraper(fetch_app_details=fetch)
    scraper.max_retries = 5
    scraper.base_backoff = 2.0
    scraper.max_backoff = 6.0

    assert scraper.get_app_metrics(PACKAGE) is None
    assert fetch.call_count == 5
    assert delays == [2, 4, 6, 6]
    assert f"Skipping {PACKAGE} after 5 fetch attempt(s): read timed out" in caplog.text


def test_skips_permanent_http_error_immediately(delays, caplog):
    fetch = Mock(side_effect=wrapped_http_error(403))

    assert PlayStoreScraper(fetch_app_details=fetch).get_app_metrics(PACKAGE) is None
    assert fetch.call_count == 1
    assert delays == []
    assert PACKAGE in caplog.text
    assert "403" in caplog.text


@pytest.mark.parametrize("outcome", [ValueError("unexpected error"), {"score": "invalid"}])
def test_unexpected_fetch_and_conversion_errors_propagate(outcome, delays):
    fetch = Mock(side_effect=[outcome])

    with pytest.raises(ValueError):
        PlayStoreScraper(fetch_app_details=fetch).get_app_metrics(PACKAGE)
    assert fetch.call_count == 1
    assert delays == []
