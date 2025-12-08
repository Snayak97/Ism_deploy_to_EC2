from pydantic import BaseModel,Field,EmailStr
from typing import Optional
from uuid import UUID
from datetime import datetime


class PlatformMasterCreate(BaseModel):
    platform_name: str = Field(..., min_length=2)
    description: str = Field(..., min_length=2)
    email: EmailStr = Field(...)  
    address: str = Field(..., min_length=3)


class PlatformMasterResponseSchema(BaseModel):
    platform_id: UUID
    platform_name: str
    description: str
    email: EmailStr
    address: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True 