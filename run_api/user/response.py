"""
Safer response class for user.
"""

from pydantic import BaseModel
from datetime import datetime


class UserResponse(BaseModel):
    username: str
    user_id: str
    created_at: datetime

    class Config:
        orm_mode = True
        from_attributes = True