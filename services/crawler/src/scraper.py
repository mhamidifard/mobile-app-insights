import random
import time
from collections.abc import Callable
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
    TARGET_REVIEWS_COUNT,
)
from google_play_scraper import Sort, app, reviews
from google_play_scraper.exceptions import ExtraHTTPError, NotFoundError
from models import AppMetrics, Review

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


class PlayStoreScraper:
    """Fetches app metrics and reviews from the Play Store with retry/backoff."""

    def __init__(
        self,
        fetch_app_details: Callable[..., Any] = app,
        fetch_reviews_page: Callable[..., Any] = reviews,
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
                delay = min(self.max_backoff, self.base_backoff * 2 ** (attempt - 1))
                logger.warning("Retrying %s in %.1fs after fetch attempt %d: %s", package_name, delay, attempt, error)
                time.sleep(delay)
                continue

            if not isinstance(payload, dict) or not _has_listing_data(payload):
                logger.warning("Skipping %s: no usable Google Play listing data.", package_name)
                return None
            return AppMetrics.from_scraped_payload(payload, datetime.now(UTC).isoformat())
        return None

    def get_latest_reviews(self, package_name: str, count: int = TARGET_REVIEWS_COUNT) -> list[dict[str, Any]]:
        # TODO: DAY 2
        pass
