from pydantic import BaseModel, Field,HttpUrl
from typing import Optional
from uuid import UUID
from datetime import datetime




class MarketPlaceCreate(BaseModel):
    marketplace_name: str = Field(..., min_length=2, )
    marketplace_code: str = Field(..., min_length=2)
    website_url: HttpUrl = Field(..., )
    country: str = Field(..., min_length=2,)
    currency: float
    is_active: Optional[bool] = Field(True,)
    api_enabled: Optional[bool] = Field(False,)
    shipping_location: str = Field(..., min_length=2)




class MarketplaceMasterResponseSchema(BaseModel):
    marketplace_id : UUID
    marketplace_name: str
    marketplace_code: str
    website_url: str
    country :str
    currency: float
    is_active: bool
    api_enabled: bool
    shipping_location: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True  
        # json_encoders = {
        #     datetime: lambda v: (
        #         v.astimezone(IST).strftime("%d-%m-%Y %H:%M:%S")
        #         if v.tzinfo else
        #         pytz.utc.localize(v).astimezone(IST).strftime("%d-%m-%Y %H:%M:%S")
        #     )
        # }