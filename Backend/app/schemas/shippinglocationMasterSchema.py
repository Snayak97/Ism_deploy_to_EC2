from pydantic import BaseModel, Field,constr

from pydantic.networks import EmailStr
from typing import Optional
from uuid import UUID
from datetime import datetime




class ShippingLocationCreateSchema(BaseModel):
    shippinglocation_code: constr(strip_whitespace=True, min_length=1)
    shippinglocation_name: constr(strip_whitespace=True, min_length=1)
    address: constr(strip_whitespace=True, min_length=1)
    pincode: constr(strip_whitespace=True, min_length=1)
    city: Optional[str] = None
    country: Optional[str] = None
    contact_person: constr(strip_whitespace=True, min_length=1)
    contact_number: int  
    is_active: Optional[bool] = False



class ShippingLocationMasterResponseSchema(BaseModel):
    shippinglocation_id : UUID
    shippinglocation_code: str
    shippinglocation_name: str
    address :str
    pincode :str
    country :str
    city: str
    country: str
    contact_person : str
    contact_number:str  
    is_active: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True  
        