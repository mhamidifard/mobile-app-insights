"""Single-page access to google-play-scraper 1.2.7's review endpoint."""

from typing import Any

from google_play_scraper import Sort
from google_play_scraper.constants.element import ElementSpecs
from google_play_scraper.constants.request import Formats
from google_play_scraper.features.reviews import _fetch_review_items


def fetch_review_page(
    package_name: str, *, lang: str, country: str, sort: Sort, count: int, continuation_token: str | None
) -> tuple[list[dict[str, Any]], str | None]:
    # The public reviews() paginates internally and suppresses page fetch failures.
    try:
        items, token = _fetch_review_items(
            Formats.Reviews.build(lang=lang, country=country), package_name,
            sort.value, count, None, None, continuation_token,
        )
    except Exception as error:
        # The pinned POST helper raises a plain Exception after repeated gateway errors.
        if error.args == ("com.google.play.gateway.proto.PlayGatewayError",):
            raise ConnectionError("Google Play review gateway rate limit") from error
        raise
    rows = [{key: spec.extract_content(item) for key, spec in ElementSpecs.Review.items()} for item in items]
    return rows, None if isinstance(token, list) else token
