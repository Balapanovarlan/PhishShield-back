from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from pydantic import BaseModel
from datetime import datetime
from app.core.database import get_db
from app.core.deps import get_current_admin
from app.core.security import hash_password
from app.models.user import User
from app.models.scan_log import ScanLog
from app.models.blacklist_entry import BlacklistEntry

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(get_current_admin)])


# --- Schemas ---

class StatsResponse(BaseModel):
    total_scans: int
    phishing_detected: int
    safe_urls: int
    model_a_scans: int
    model_b_scans: int


class BlacklistEntryOut(BaseModel):
    id: int
    domain: str
    url_example: str | None
    total_scans: int
    phishing_count: int
    risk_score_avg: float
    explanations: list[str] | None
    promoted_at: datetime | None
    created_at: datetime

    class Config:
        from_attributes = True


class BlacklistListResponse(BaseModel):
    items: list[BlacklistEntryOut]
    total: int


class UserOut(BaseModel):
    id: int
    email: str
    name: str
    role: str
    is_blocked: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    items: list[UserOut]
    total: int


class CreateUserRequest(BaseModel):
    name: str
    email: str
    password: str
    role: str = "user"


# --- Stats ---

@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    total = db.query(func.count(ScanLog.id)).scalar() or 0
    phishing = db.query(func.count(ScanLog.id)).filter(ScanLog.is_phishing == True).scalar() or 0
    safe = total - phishing

    model_a = db.query(func.count(ScanLog.id)).filter(
        ScanLog.method.ilike("%html%") | ScanLog.method.ilike("%model a%") | ScanLog.method.ilike("%hybrid%")
    ).scalar() or 0
    model_b = db.query(func.count(ScanLog.id)).filter(
        ScanLog.method.ilike("%url%") | ScanLog.method.ilike("%model b%")
    ).scalar() or 0

    return StatsResponse(
        total_scans=total,
        phishing_detected=phishing,
        safe_urls=safe,
        model_a_scans=model_a,
        model_b_scans=model_b,
    )


# --- Blacklist ---

@router.get("/blacklist", response_model=BlacklistListResponse)
def get_blacklist(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    total = db.query(func.count(BlacklistEntry.id)).filter(
        BlacklistEntry.promoted_at.isnot(None)
    ).scalar() or 0

    items = (
        db.query(BlacklistEntry)
        .filter(BlacklistEntry.promoted_at.isnot(None))
        .order_by(BlacklistEntry.promoted_at.desc())
        .offset((page - 1) * size)
        .limit(size)
        .all()
    )

    return BlacklistListResponse(
        items=[BlacklistEntryOut.model_validate(item) for item in items],
        total=total,
    )


@router.delete("/blacklist/{entry_id}", status_code=status.HTTP_204_NO_CONTENT)
def remove_from_blacklist(entry_id: int, db: Session = Depends(get_db)):
    entry = db.query(BlacklistEntry).filter(BlacklistEntry.id == entry_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    entry.promoted_at = None
    entry.phishing_count = 0
    db.commit()


# --- Users ---

@router.get("/users", response_model=UserListResponse)
def get_users(
    page: int = Query(1, ge=1),
    size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    total = db.query(func.count(User.id)).scalar() or 0
    items = (
        db.query(User)
        .order_by(User.created_at.desc())
        .offset((page - 1) * size)
        .limit(size)
        .all()
    )
    return UserListResponse(
        items=[UserOut.model_validate(item) for item in items],
        total=total,
    )


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(body: CreateUserRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == body.email).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already registered")

    if body.role not in ("user", "admin"):
        raise HTTPException(status_code=400, detail="Role must be 'user' or 'admin'")

    user = User(
        email=body.email,
        name=body.name,
        hashed_password=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return UserOut.model_validate(user)


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    db.delete(user)
    db.commit()


@router.patch("/users/{user_id}/block", status_code=status.HTTP_200_OK)
def block_user(user_id: int, db: Session = Depends(get_db), admin: User = Depends(get_current_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot block yourself")
    user.is_blocked = True
    db.commit()
    return {"detail": "User blocked"}


@router.patch("/users/{user_id}/unblock", status_code=status.HTTP_200_OK)
def unblock_user(user_id: int, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.is_blocked = False
    db.commit()
    return {"detail": "User unblocked"}
