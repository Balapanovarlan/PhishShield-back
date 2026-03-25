from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session
from app.models.blacklist_entry import BlacklistEntry

PROMOTION_THRESHOLD = 5


def record_scan(
    db: Session,
    domain: str,
    url: str,
    is_phishing: bool,
    risk_score: float,
    explanations: list[str],
) -> None:
    """Called after every ML scan. Updates counters, promotes if threshold met."""
    entry = db.query(BlacklistEntry).filter_by(domain=domain).first()

    if not entry:
        entry = BlacklistEntry(
            domain=domain,
            url_example=url,
            total_scans=0,
            phishing_count=0,
            risk_score_avg=0.0,
            explanations=[],
        )
        db.add(entry)

    entry.total_scans += 1

    if is_phishing:
        entry.phishing_count += 1

    # Rolling average risk score
    prev_total = entry.total_scans - 1
    if prev_total > 0:
        entry.risk_score_avg = (entry.risk_score_avg * prev_total + risk_score) / entry.total_scans
    else:
        entry.risk_score_avg = risk_score

    # Merge unique explanations (cap at 10)
    existing = entry.explanations or []
    merged = list(dict.fromkeys(existing + explanations))[:10]
    entry.explanations = merged

    # Promote to blacklist if threshold met
    if entry.phishing_count >= PROMOTION_THRESHOLD and entry.promoted_at is None:
        entry.promoted_at = datetime.utcnow()

    db.commit()


def is_blacklisted(db: Session, domain: str) -> Optional[BlacklistEntry]:
    """Returns the entry if the domain is on the auto-blacklist."""
    return (
        db.query(BlacklistEntry)
        .filter(
            BlacklistEntry.domain == domain,
            BlacklistEntry.promoted_at.isnot(None),
        )
        .first()
    )
