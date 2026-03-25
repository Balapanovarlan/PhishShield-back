import os
from fastapi import FastAPI, HTTPException, Header, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Optional

from app.core.database import engine, Base, get_db
from app.core.security import hash_password
from app.core.deps import get_current_admin, get_optional_user
from app.models import User, ScanLog
from app.services.hybrid_detector import HybridDetector
from app.services.data_fetcher import DataFetcher
from app.api.auth import router as auth_router
from app.api.admin import router as admin_router

app = FastAPI(title="PhishShield API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth_router)
app.include_router(admin_router)

# Initialize detector
detector = HybridDetector()


class URLCheckRequest(BaseModel):
    url: str


@app.on_event("startup")
def on_startup():
    """Create tables and seed admin user."""
    Base.metadata.create_all(bind=engine)

    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.role == "admin").first()
        if not admin:
            admin = User(
                email="admin@phishshield.local",
                name="Admin",
                hashed_password=hash_password(os.getenv("ADMIN_PASSWORD", "admin123")),
                role="admin",
            )
            db.add(admin)
            db.commit()
            print("Seeded admin user: admin@phishshield.local")
    finally:
        db.close()


@app.get("/")
def read_root():
    return {"message": "Welcome to PhishShield Phishing Detection API"}


@app.post("/check")
def check_url(
    request: URLCheckRequest,
    locale: Optional[str] = Header(None),
    db: Session = Depends(get_db),
    user: User | None = Depends(get_optional_user),
):
    if not request.url:
        raise HTTPException(status_code=400, detail="URL is required")

    active_locale = locale if locale in ["en", "ru"] else "en"

    try:
        result = detector.detect(request.url, locale=active_locale, db=db)

        # Log scan
        from urllib.parse import urlparse
        parsed = urlparse(request.url)
        domain = (parsed.netloc or request.url.split('/')[0]).lower().strip()

        scan_log = ScanLog(
            url=request.url,
            domain=domain,
            is_phishing=result["is_phishing"],
            risk_score=result.get("risk_score"),
            method=result.get("method"),
            explanations=result.get("explanations"),
            user_id=user.id if user else None,
        )
        db.add(scan_log)
        db.commit()

        return result
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/refresh-data")
def refresh_data(admin: User = Depends(get_current_admin)):
    fetcher = DataFetcher()
    fetcher.fetch_phishtank()
    fetcher.fetch_tranco()
    detector.load_lists()
    return {"message": "Threat intelligence databases updated successfully."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
