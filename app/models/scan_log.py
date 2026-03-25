from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, Float, DateTime, ForeignKey, JSON
from app.core.database import Base


class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(String, nullable=False)
    domain = Column(String, index=True, nullable=False)
    is_phishing = Column(Boolean, nullable=False)
    risk_score = Column(Float)
    method = Column(String)
    explanations = Column(JSON)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
