from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List
from uuid import UUID
from app.database import get_db
from app.models.user import User
from app.models.target import Target, TargetType, TargetStatus
from app.schemas.target import TargetCreate, TargetResponse
from app.schemas.pagination import PaginatedResponse
from app.services.auth_service import get_current_user
from app.utils.security import encrypt_value

router = APIRouter()

@router.get("/", response_model=PaginatedResponse[TargetResponse])
def list_targets(
    page: int = Query(1, ge=1, description="Page number"),
    size: int = Query(20, ge=1, le=100, description="Items per page"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    query = db.query(Target).filter(Target.user_id == current_user.id)
    total = query.count()
    targets = query.order_by(Target.created_at.desc()).offset((page - 1) * size).limit(size).all()
    return PaginatedResponse.create(items=targets, total=total, page=page, size=size)

@router.post("/", response_model=TargetResponse, status_code=201)
def create_target(
    data: TargetCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # URL doğrulama: http:// veya https:// ile başlamalı
    if not data.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL. Must start with http:// or https://")

    target = Target(
        user_id=current_user.id,
        name=data.name or data.url,
        target_type=data.target_type,
        url=data.url,
        auth_header=encrypt_value(data.auth_header) if data.auth_header else None,
        status=TargetStatus.VERIFIED  # MVP'de otomatik doğrula, ileride domain ownership check
    )
    db.add(target)
    db.commit()
    db.refresh(target)
    return target

@router.get("/{target_id}", response_model=TargetResponse)
def get_target(
    target_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    target = db.query(Target).filter(
        Target.id == target_id,
        Target.user_id == current_user.id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    return target

@router.delete("/{target_id}", status_code=204)
def delete_target(
    target_id: UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    target = db.query(Target).filter(
        Target.id == target_id,
        Target.user_id == current_user.id
    ).first()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    db.delete(target)
    db.commit()
