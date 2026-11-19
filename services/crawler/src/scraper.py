import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.error import HTTPError, URLError

from configs import (
    BASE_BACKOFF,
    COUNTRY_CODE,
    FALLBACK_VERSION_LABEL,
    INITIAL_ADAPTIVE_DELAY,
    LANG_CODE,
    MAX_ADAPTIVE_DELAY,
    MAX_BACKOFF,
    MAX_RETRIES,
    MIN_ADAPTIVE_DELAY,
    REVIEW_LOCALES,
    REVIEWS_BATCH_SIZE,
    TARGET_REVIEWS_COUNT,
)
from google_play_scraper import Sort, app
from google_play_scraper.exceptions import ExtraHTTPError, NotFoundError
from models import AppMetrics, Review
from review_pages import fetch_review_page

from utils.logging_setup import get_logger

logger = get_logger(__name__)


def _has_listing_data(payload: dict[str, Any]) -> bool:
    title = payload.get("title")
    if isinstance(title, str) and title.strip():
        return True

    # Even an unparsed page can have an appId, URL, and fallback version.
    version = payload.get("version")
    if isinstance(version, str) and version.strip() and version.strip() != FALLBACK_VERSION_LABEL:
        return True
    metrics = ("minInstalls", "realInstalls", "score", "ratings", "reviews", "adSupported", "updated")
    return any(payload.get(key) is not None for key in metrics)


def _is_transient_fetch_error(error: Exception) -> bool:
    # google-play-scraper 1.2.7 preserves urllib's HTTPError as the context.
    http_error = error.__context__ if isinstance(error, ExtraHTTPError) else error
    if isinstance(http_error, HTTPError):
        return http_error.code in (408, 429) or 500 <= http_error.code < 600
    return isinstance(error, (URLError, ConnectionError, TimeoutError))


@dataclass
class _LocaleReviews:
    lang: str
    country: str
    token: Any = None
    seen_tokens: set[str] = field(default_factory=set)
    dated: deque[tuple[datetime, Review]] = field(default_factory=deque)
    undated: dict[str, Review] = field(default_factory=dict)
    exhausted: bool = False

    def add_page(self, rows: list[dict[str, Any]], token: Any, scraped_at: str) -> None:
        for payload in rows:
            review = Review.from_scraped_payload(
                payload, scraped_at, source_language=self.lang, source_country=self.country,
            )
            if review is None:
                continue
            if review.review_at is None:
                self.undated.setdefault(review.review_id, review)
            else:
                self.dated.append((datetime.fromisoformat(review.review_at), review))

        # Injected public-client tokens can wrap the same cursor in different objects.
        value = getattr(token, "token", token)
        self.exhausted = not rows or value is None or isinstance(value, list) or value in self.seen_tokens
        if not self.exhausted:
            self.seen_tokens.add(value)
            self.token = token


class PlayStoreScraper:
    """Fetches app metrics and reviews from the Play Store with retry/backoff."""

    def __init__(
        self,
        fetch_app_details: Callable[..., Any] = app,
        fetch_reviews_page: Callable[..., Any] = fetch_review_page,
    ) -> None:
        """Accept the Play Store calls as injectable dependencies; the defaults hit the real store."""
        self.fetch_app_details = fetch_app_details
        self.fetch_reviews_page = fetch_reviews_page

        self.max_retries = MAX_RETRIES
        self.base_backoff = BASE_BACKOFF
        self.max_backoff = MAX_BACKOFF

        self.adaptive_delay = INITIAL_ADAPTIVE_DELAY
        self.min_delay = MIN_ADAPTIVE_DELAY
        self.max_delay = MAX_ADAPTIVE_DELAY

    def _retry_delay_seconds(self, attempt: int) -> float:
        return min(self.max_backoff, self.base_backoff * 2 ** (attempt - 1))

    def get_app_metrics(self, package_name: str) -> AppMetrics | None:
        """Fetch one listing, retrying transient failures within the attempt budget."""
        for attempt in range(1, self.max_retries + 1):
            try:
                payload = self.fetch_app_details(package_name, lang=LANG_CODE, country=COUNTRY_CODE)
            except NotFoundError:
                logger.warning("Skipping %s: Google Play listing not found.", package_name)
                return None
            except (ExtraHTTPError, URLError, ConnectionError, TimeoutError) as error:
                if not _is_transient_fetch_error(error) or attempt == self.max_retries:
                    logger.warning("Skipping %s after %d fetch attempt(s): %s", package_name, attempt, error)
                    return None
                delay = self._retry_delay_seconds(attempt)
                logger.warning("Retrying %s in %.1fs after fetch attempt %d: %s", package_name, delay, attempt, error)
                time.sleep(delay)
                continue

            if not isinstance(payload, dict) or not _has_listing_data(payload):
                logger.warning("Skipping %s: no usable Google Play listing data.", package_name)
                return None
            return AppMetrics.from_scraped_payload(payload, datetime.now(UTC).isoformat())
        return None

    def get_latest_reviews(self, package_name: str, count: int = TARGET_REVIEWS_COUNT) -> list[dict[str, Any]]:
        """Merge newest-first locale feeds, using configured locale order to break ties."""
        limit = min(count, TARGET_REVIEWS_COUNT)
        if limit <= 0:
            return []

        feeds = [_LocaleReviews(lang, country) for lang, country in REVIEW_LOCALES]
        selected: dict[str, Review] = {}
        failure = None
        while len(selected) < limit:
            # Each live feed needs a dated head before the next globally newest item is known.
            if failure is None:
                for feed in feeds:
                    if feed.dated or feed.exhausted:
                        continue
                    try:
                        page_size = min(REVIEWS_BATCH_SIZE, limit - len(selected))
                        rows, token = self._request_review_page(package_name, feed, page_size)
                    except Exception as error:
                        failure = (feed.lang, feed.country, error)
                        break
                    feed.add_page(rows, token, datetime.now(UTC).isoformat())
                if failure is None and any(not feed.dated and not feed.exhausted for feed in feeds):
                    continue

            ready = (feed for feed in feeds if feed.dated)
            newest = max(ready, key=lambda feed: feed.dated[0][0], default=None)
            if newest is None:
                break
            _, review = newest.dated.popleft()
            selected.setdefault(review.review_id, review)

        for feed in feeds:
            for review in feed.undated.values():
                if len(selected) == limit:
                    break
                selected.setdefault(review.review_id, review)
        if failure is not None:
            lang, country, error = failure
            logger.warning(
                "Review fetch failed for %s (%s/%s): %s; returning %d reviews",
                package_name, lang, country, error, len(selected),
            )
        return [review.to_record() for review in selected.values()]

    def _request_review_page(
        self, package_name: str, feed: _LocaleReviews, count: int
    ) -> tuple[list[dict[str, Any]], Any]:
        attempt = 1
        while True:
            try:
                return self.fetch_reviews_page(
                    package_name, lang=feed.lang, country=feed.country, sort=Sort.NEWEST,
                    count=count, continuation_token=feed.token,
                )
            except (ExtraHTTPError, URLError, ConnectionError, TimeoutError) as error:
                if attempt >= self.max_retries or not _is_transient_fetch_error(error):
                    raise
                delay = self._retry_delay_seconds(attempt)
                logger.warning(
                    "Retrying reviews for %s (%s/%s) in %.1fs: %s",
                    package_name, feed.lang, feed.country, delay, error,
                )
                time.sleep(delay)
                attempt += 1
