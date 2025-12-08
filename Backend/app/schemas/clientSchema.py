from pydantic import BaseModel, Field
from pydantic.networks import EmailStr
from typing import Optional
from uuid import UUID
from datetime import datetime
from app.schemas.userSchema import UserResponseSchema

# -------------------
# Client and Client Admin
# -------------------

class ClientResponseSchema(BaseModel):
    client_id: int
    org_name: str
    org_email: EmailStr
    created_by_user_id: Optional[UUID]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True

class ClientAdminCreateSchema(BaseModel):
    user_name: str = Field(..., min_length=3)
    email: EmailStr
    mobile_number: Optional[str] = None
    org_name: str = Field(..., min_length=3)
    org_email: EmailStr

class ClientAdminResponseSchema(BaseModel):
    user: Optional[UserResponseSchema] = None
    client: Optional[ClientResponseSchema] = None

    class Config:
        from_attributes = True

class ClientAdminUpdateSchema(BaseModel):
    user_name: Optional[str] = Field(None, min_length=3)
    email: Optional[EmailStr] = None
    mobile_number: Optional[str] = None
    org_name: Optional[str] = Field(None, min_length=3)
    org_email: Optional[EmailStr] = None

# -------------------
# Client User
# -------------------

class ClientUserCreateSchema(BaseModel):
    user_name: str = Field(..., min_length=3)
    email: EmailStr
    mobile_number: Optional[str] = None
    role_name : str=Field(..., min_length=2)
    department_name: str = Field(..., min_length=2)
    
class ClientUserResponseSchema(BaseModel):
    user: Optional[UserResponseSchema] = None
    org_name: Optional[str] = Field(default=None, min_length=3)
    org_email: Optional[EmailStr] = None

    class Config:
        from_attributes = True

class ClientUserUpdateSchema(BaseModel):
    user_name: Optional[str] = None
    email: Optional[EmailStr] = None
    mobile_number: Optional[str] = None
    role_name: Optional[str] = None
    department_name: Optional[str] = None