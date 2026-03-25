from datetime import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, JSON
from app.core.database import Base


class BlacklistEntry(Base):
    __tablename__ = "blacklist_entries"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    url_example = Column(String)
    total_scans = Column(Integer, default=0)
    phishing_count = Column(Integer, default=0)
    risk_score_avg = Column(Float, default=0.0)
    explanations = Column(JSON)
    promoted_at = Column(DateTime, nullable=True)  # NULL = not yet blacklisted
    created_at = Column(DateTime, default=datetime.utcnow)
