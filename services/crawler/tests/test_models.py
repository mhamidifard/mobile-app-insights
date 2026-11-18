from configs import FALLBACK_VERSION_LABEL
from models import AppMetrics, Review

from tests.builders import REVIEWED_AT, STORE_UPDATED_EPOCH_SECONDS, raw_review

SCRAPED_AT = "2026-11-14T10:00:00+00:00"


def test_translates_a_full_app_payload_into_the_metrics_model():
    app_payload = {
        "minInstalls": 1000000,
        "realInstalls": 950000,
        "score": 4.567,
        "ratings": 50000,
        "reviews": 3000,
        "version": "3.2.1",
        "adSupported": True,
        "updated": STORE_UPDATED_EPOCH_SECONDS,
    }

    metrics = AppMetrics.from_scraped_payload(app_payload, SCRAPED_AT)

    assert metrics.ad_supported is True
    assert metrics.to_record() == {
        "min_installs": 1000000,
        "real_installs": 950000,
        "score": 4.57,
        "ratings": 50000,
        "reviews_count": 3000,
        "version": "3.2.1",
        "ad_supported": True,
        "store_updated_at": "2024-11-14T17:30:00+00:00",
        "scraped_at": SCRAPED_AT,
    }


def test_minimal_app_payload_falls_back_to_the_default_version_and_score():
    metrics = AppMetrics.from_scraped_payload({}, SCRAPED_AT)

    assert metrics.ad_supported is False
    assert metrics.to_record() == {
        "min_installs": None,
        "real_installs": None,
        "score": 0.0,
        "ratings": None,
        "reviews_count": None,
        "version": FALLBACK_VERSION_LABEL,
        "ad_supported": False,
        "store_updated_at": None,
        "scraped_at": SCRAPED_AT,
    }


def test_translates_a_full_review_payload_into_the_review_model():
    review = Review.from_scraped_payload(raw_review("r1"), SCRAPED_AT)

    assert review.review_id == "r1"
    assert review.user_name == "Reviewer"
    assert review.score == 5
    assert review.thumbs_up_count == 1
    assert review.content == "content r1"
    assert review.review_at == REVIEWED_AT.isoformat()
    assert review.scraped_at == SCRAPED_AT


def test_review_without_an_id_is_dropped():
    assert Review.from_scraped_payload({"userName": "Reviewer"}, SCRAPED_AT) is None
