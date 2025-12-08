from pydantic import BaseModel, HttpUrl,Field
from typing import Optional
from uuid import UUID
from datetime import datetime


class SellingPlatformCreate(BaseModel):
    selling_platform_name: str = Field(..., min_length=2)
    selling_platform_type: str = Field(..., min_length=2)
    country: Optional[str] = Field(...,min_length=2)
    currency: float 
    sales_channel_url: HttpUrl = Field(...)
    is_active: Optional[bool] = Field(default=True)
    api_enabled: Optional[bool] = Field(default=False)


class SellingPlatformResponseSchema(BaseModel):
    selling_platform_id: UUID
    selling_platform_name: str
    selling_platform_type: str
    country: Optional[str]
    currency: float
    sales_channel_url: str
    is_active: bool
    api_enabled: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
