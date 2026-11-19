from datetime import UTC, datetime
from types import SimpleNamespace
from unittest.mock import Mock, call

import pytest
from google_play_scraper import Sort
from google_play_scraper.constants.request import Formats
from google_play_scraper.exceptions import NotFoundError
from review_pages import fetch_review_page
from scraper import PlayStoreScraper

from tests.builders import raw_review

PACKAGE = "org.telegram.messenger"


@pytest.fixture
def delays(monkeypatch):
    recorded = []
    monkeypatch.setattr("scraper.time.sleep", recorded.append)
    monkeypatch.setattr("scraper.REVIEW_LOCALES", [("fa", "ir")])
    return recorded


def dated(review_id, instant, content):
    return {**raw_review(review_id, datetime.fromisoformat(instant)), "content": content}


def test_merges_by_instant_across_pages_and_locales(monkeypatch, delays):
    monkeypatch.setattr("scraper.REVIEW_LOCALES", [("fa", "ir"), ("en", "us")])
    monkeypatch.setattr("scraper.REVIEWS_BATCH_SIZE", 3)
    old = dated("shared", "2026-01-01T13:30:00+03:30", "older")
    new = dated("shared", "2026-01-01T12:00:00+00:00", "newer")
    tie = "2026-01-01T11:00:00+00:00"
    pages = {
        ("fa", None): ([{"reviewId": "undated"}, dated("fa1", tie, "a"), {"content": "missing ID"}], "next"),
        ("fa", "next"): ([dated("fa2", tie, "b"), old, old], None),
        ("en", None): ([new, dated("fa1", tie, "other copy"), dated("en1", tie, "c")], "next"),
        ("en", "next"): ([dated("en2", "2026-01-01T09:00:00+00:00", "d")], None),
    }
    fetch = Mock(side_effect=lambda app, **kw: pages[(kw["lang"], kw["continuation_token"])])

    records = PlayStoreScraper(fetch_reviews_page=fetch).get_latest_reviews(PACKAGE, count=6)

    assert [r["review_id"] for r in records] == ["shared", "fa1", "fa2", "en1", "en2", "undated"]
    assert [(r["content"], r["source_language"], r["source_country"]) for r in records[:2]] == [
        ("newer", "en", "us"),
        ("a", "fa", "ir"),
    ]
    assert records[0]["review_at"] == new["at"].isoformat()
    assert records[-1]["review_at"] is None
    assert all(datetime.fromisoformat(r["scraped_at"]).utcoffset() == UTC.utcoffset(None) for r in records)
    assert fetch.call_args_list == [
        call(PACKAGE, lang=lang, country=country, sort=Sort.NEWEST, count=size, continuation_token=token)
        for lang, country, size, token in [
            ("fa", "ir", 3, None), ("en", "us", 3, None), ("fa", "ir", 3, "next"), ("en", "us", 2, "next"),
        ]
    ]
    assert delays == []


def test_later_locale_can_fill_entire_limit(monkeypatch, delays):
    monkeypatch.setattr("scraper.REVIEW_LOCALES", [("fa", "ir"), ("en", "us")])
    fetch = Mock(side_effect=[
        ([dated("older", "2026-01-01T11:30:00+03:30", "old")], "more-fa"),
        ([dated("newer", "2026-01-01T10:00:00+00:00", "new")], "more-en"),
    ])
    records = PlayStoreScraper(fetch_reviews_page=fetch).get_latest_reviews(PACKAGE, count=1)
    assert [r["review_id"] for r in records] == ["newer"]
    assert fetch.call_count == 2


@pytest.mark.parametrize("count", [0, -1])
def test_nonpositive_count_skips_fetch(count):
    fetch = Mock()
    assert PlayStoreScraper(fetch_reviews_page=fetch).get_latest_reviews(PACKAGE, count) == []
    fetch.assert_not_called()


def test_caps_unique_results_and_shrinks_last_request(monkeypatch, delays):
    monkeypatch.setattr("scraper.REVIEWS_BATCH_SIZE", 200)

    def fetch_batch(package_name, *, count, continuation_token, **kwargs):
        start = int(continuation_token or 0)
        rows = [raw_review(str(i)) for i in range(start, start + count)]
        if start == 0:
            rows[0] = rows[1]
        return rows, str(start + count)

    fetch = Mock(side_effect=fetch_batch)
    records = PlayStoreScraper(fetch_reviews_page=fetch).get_latest_reviews(PACKAGE, 1200)

    assert [r["review_id"] for r in records] == [str(i) for i in range(1, 1001)]
    assert [c.kwargs["count"] for c in fetch.call_args_list] == [200] * 5 + [1]


@pytest.mark.parametrize("terminal_page", [
    ([], SimpleNamespace(token="unused")),
    ([raw_review("two")], SimpleNamespace(token=None)),
    ([raw_review("two")], SimpleNamespace(token="cursor")),
])
def test_empty_terminal_or_repeated_cursor_stops_locale(terminal_page, delays):
    first_token = SimpleNamespace(token="cursor")
    fetch = Mock(side_effect=[([raw_review("one")], first_token), terminal_page])
    records = PlayStoreScraper(fetch_reviews_page=fetch).get_latest_reviews(PACKAGE)

    assert [r["review_id"] for r in records] == ["one"] + [r["reviewId"] for r in terminal_page[0]]
    assert fetch.call_count == 2
    assert fetch.call_args.kwargs["continuation_token"] is first_token


def test_transient_page_failure_retries_same_cursor(delays):
    fetch = Mock(side_effect=[
        ([raw_review("one")], "cursor"), TimeoutError("timeout"), ([raw_review("two")], None),
    ])
    scraper = PlayStoreScraper(fetch_reviews_page=fetch)
    records = scraper.get_latest_reviews(PACKAGE, 2)
    assert [r["review_id"] for r in records] == ["one", "two"]
    assert fetch.call_args_list[1] == fetch.call_args_list[2]
    assert fetch.call_args.kwargs["continuation_token"] == "cursor"
    assert delays == [min(scraper.base_backoff, scraper.max_backoff)]


@pytest.mark.parametrize("error, attempts", [(TimeoutError("timeout"), 3), (NotFoundError("gone"), 1)])
def test_failure_returns_buffered_reviews_and_stops_requests(error, attempts, monkeypatch, delays, caplog):
    monkeypatch.setattr("scraper.REVIEW_LOCALES", [("fa", "ir"), ("en", "us")])
    fetch = Mock(side_effect=[
        ([dated("first", "2026-01-02T00:00:00+00:00", "a")], "fa-next"),
        ([{"reviewId": "undated"}, dated("buffered", "2026-01-01T00:00:00+00:00", "b")], "en-next"),
        *([error] * attempts),
    ])
    scraper = PlayStoreScraper(fetch_reviews_page=fetch)
    scraper.max_retries = 3
    records = scraper.get_latest_reviews(PACKAGE, 4)
    assert [r["review_id"] for r in records] == ["first", "buffered", "undated"]
    assert fetch.call_count == 2 + attempts
    assert all(c == fetch.call_args_list[2] for c in fetch.call_args_list[2:])
    assert len(delays) == attempts - 1
    assert PACKAGE in caplog.text and "fa/ir" in caplog.text
    assert str(error) in caplog.text and "returning 3 reviews" in caplog.text


@pytest.mark.parametrize("cursor, expected", [(None, None), ([], None), ("next", "next")])
def test_adapter_decodes_exactly_one_page(monkeypatch, cursor, expected):
    item = ["id", ["Author"], 4, None, "text", [1731605400], 2]
    fetch = Mock(return_value=([item], cursor))
    monkeypatch.setattr("review_pages._fetch_review_items", fetch)
    rows, token = fetch_review_page(PACKAGE, lang="en", country="us", sort=Sort.NEWEST, count=2,
                                    continuation_token="previous")
    fetch.assert_called_once_with(Formats.Reviews.build(lang="en", country="us"), PACKAGE,
                                  Sort.NEWEST.value, 2, None, None, "previous")
    assert token == expected
    assert [(r["reviewId"], r["userName"], r["content"], r["score"]) for r in rows] == [("id", "Author", "text", 4)]
    assert rows[0]["at"] == datetime.fromtimestamp(1731605400)


def test_adapter_surfaces_pinned_client_gateway_failure(monkeypatch):
    fetch = Mock(side_effect=Exception("com.google.play.gateway.proto.PlayGatewayError"))
    monkeypatch.setattr("review_pages._fetch_review_items", fetch)
    with pytest.raises(ConnectionError, match="gateway"):
        fetch_review_page(PACKAGE, lang="en", country="us", sort=Sort.NEWEST, count=1, continuation_token=None)
    assert fetch.call_count == 1
