"""
Routes for chutes.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import or_, func
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from typing import Optional
from run_api.chute.schemas import Chute
from run_api.chute.response import ChuteResponse
from run_api.user.schemas import User
from run_api.user.service import get_current_user
from run_api.image.schemas import Image
from run_api.database import get_db_session
from run_api.pagination import PaginatedResponse

router = APIRouter()


@router.get("/", response_model=PaginatedResponse)
async def list_chutes(
    include_public: Optional[bool] = False,
    name: Optional[str] = None,
    image: Optional[str] = None,
    page: Optional[int] = 0,
    limit: Optional[int] = 25,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    List (and optionally filter/paginate) chutes.
    """
    query = select(Chute)

    # Filter by public and/or only the user's chutes.
    if include_public:
        query = query.where(
            or_(
                Chute.public.is_(True),
                Chute.user_id == current_user.user_id,
            )
        )
    else:
        query = query.where(Chute.user_id == current_user.user_id)

    # Filter by name/tag/etc.
    if name and name.strip():
        query = query.where(Chute.name.ilike(f"%{name}%"))
    if image and image.strip():
        query = query.where(
            or_(
                Image.name.ilike("%{image}%"),
                Image.tag.ilike("%{image}%"),
            )
        )

    # Perform a count.
    total_query = select(func.count()).select_from(query.subquery())
    total_result = await db.execute(total_query)
    total = total_result.scalar() or 0

    # Pagination.
    query = query.offset((page or 0) * (limit or 25)).limit((limit or 25))

    result = await db.execute(query)
    return {
        "total": total,
        "page": page,
        "limit": limit,
        "items": [ChuteResponse.from_orm(item) for item in result.scalars().all()],
    }


@router.get("/{chute_id}")
async def get_chute(
    chute_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Load a single chute by ID.
    """
    query = (
        select(Chute)
        .where(or_(Chute.public.is_(True), Chute.user_id == current_user.user_id))
        .where(Chute.chute_id == chute_id)
    )
    result = await db.execute(query)
    chute = result.scalar_one_or_none()
    if not chute:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chute not found, or does not belong to you",
        )
    return chute


@router.delete("/{chute_id}")
async def delete_chute(
    chute_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_user: User = Depends(get_current_user),
):
    """
    Delete a chute by ID.
    """
    query = (
        select(Chute)
        .where(Chute.user_id == current_user.user_id)
        .where(Chute.chute_id == chute_id)
    )
    result = await db.execute(query)
    chute = result.scalar_one_or_none()
    if not chute:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chute not found, or does not belong to you",
        )
    await db.delete(chute)
    await db.commit()
    return {"chute_id": chute_id, "deleted": True}