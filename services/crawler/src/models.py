from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Any

from configs import FALLBACK_VERSION_LABEL


@dataclass(frozen=True)
class Review:
    """One Play Store review, translated from the raw scraper payload into the reviews-table shape."""

    review_id: str
    user_name: str | None
    score: int | None
    thumbs_up_count: int
    content: str
    review_at: str | None
    scraped_at: str
    source_language: str | None = None
    source_country: str | None = None

    @classmethod
    def from_scraped_payload(
        cls, payload: dict[str, Any], scraped_at: str, *,
        source_language: str | None = None, source_country: str | None = None,
    ) -> "Review | None":
        """Translate a Play Store review with a usable ID into a stored observation."""
        review_id = payload.get("reviewId")
        if not isinstance(review_id, str) or not review_id.strip():
            return None

        reviewed_at = payload.get("at")
        if reviewed_at is not None and reviewed_at.utcoffset() is None:
            # google-play-scraper returns naive review times in the process's local timezone.
            reviewed_at = reviewed_at.astimezone(UTC)

        return cls(
            review_id=review_id,
            user_name=payload.get("userName"),
            score=payload.get("score"),
            thumbs_up_count=payload.get("thumbsUpCount") or 0,
            content=payload.get("content") or "",
            review_at=reviewed_at.isoformat() if reviewed_at is not None else None,
            scraped_at=scraped_at,
            source_language=source_language,
            source_country=source_country,
        )

    def to_record(self) -> dict[str, Any]:
        """Return the review fields consumed by upsert_reviews."""
        return asdict(self)


@dataclass(frozen=True)
class AppMetrics:
    """One app's store metrics, translated from the raw scraper payload into the app_metrics-table shape."""

    min_installs: int | None
    real_installs: int | None
    score: float
    ratings: int | None
    reviews_count: int | None
    version: str
    ad_supported: bool
    store_updated_at: str | None
    scraped_at: str

    @classmethod
    def from_scraped_payload(cls, payload: dict[str, Any], scraped_at: str) -> "AppMetrics":
        """Translate Play Store details into one observation at the supplied scrape time."""
        updated = payload.get("updated")
        score = payload.get("score")
        version = payload.get("version")
        return cls(
            min_installs=payload.get("minInstalls"),
            real_installs=payload.get("realInstalls"),
            score=round(float(score), 2) if score is not None else 0.0,
            ratings=payload.get("ratings"),
            reviews_count=payload.get("reviews"),
            version=version if version is not None else FALLBACK_VERSION_LABEL,
            ad_supported=bool(payload.get("adSupported")),
            store_updated_at=datetime.fromtimestamp(updated, tz=UTC).isoformat() if updated is not None else None,
            scraped_at=scraped_at,
        )

    def to_record(self) -> dict[str, Any]:
        """Return the observation fields consumed by insert_app_metrics."""
        return asdict(self)

