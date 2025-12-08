from pydantic import BaseModel, Field
from pydantic.networks import EmailStr
from typing import Optional, List
from uuid import UUID
from datetime import datetime, date
from enum import Enum
from zoneinfo import ZoneInfo


class UserCreateSchema(BaseModel):
    user_name: str = Field(..., min_length=3)
    email: EmailStr
    password: str = Field(..., min_length=6)
    mobile_number: Optional[str] = None
    department_id: Optional[int] = None
    client_id: Optional[int] = None

class UserResponseSchema(BaseModel):
    user_id: UUID
    normal_user_id: int
    user_name: str
    email: EmailStr
    mobile_number: Optional[str]
    is_verified: bool
    is_active: bool
    must_reset_password: bool
    last_active_date: Optional[datetime] = None
    last_deactive_date: Optional[datetime] = None
    role_name: Optional[str] = None
    department_name: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
        json_encoders = {
            datetime: lambda v: v.astimezone(ZoneInfo("Asia/Kolkata")).strftime('%Y-%m-%d %H:%M:%S')
        }

class UserUpdatePutSchema(BaseModel):
    user_name: str
    email: EmailStr
    mobile_number: str

class UserUpdatePatchSchema(BaseModel):
    user_name: Optional[str] = None
    email: Optional[EmailStr] = None
    mobile_number: Optional[str] = None
    

class UserLoginSchema(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=6)

class ChangePasswordSchema(BaseModel):
    old_password: str = Field(..., min_length=6)
    new_password: str = Field(..., min_length=6)
    confirm_password: str = Field(..., min_length=6)

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=8)
    new_password: str = Field(..., min_length=6)

# -------------------
# Permission Schemas
# -------------------

class PermissionEnum(str, Enum):
    view = "View"
    create = "Create"
    edit = "Edit"
    delete = "Delete"

class ModulePermissionSchema(BaseModel):
    module_name: str  # e.g., "Product", "Invoice"
    permissions: List[PermissionEnum]

class UserWithPermissionsResponse(BaseModel):
    user_id: UUID
    user_name: str
    email: EmailStr
    role_name: Optional[str] = None
    department_name: Optional[str] = None
    permissions: List[ModulePermissionSchema]

    class Config:
        from_attributes = True

class PermissionBase(BaseModel):
    module_name: str
    permission_name: List[PermissionEnum]

    class Config:
        from_attributes = True

class PermissionCreate(PermissionBase):
    pass

class PermissionResponse(PermissionBase):
    permission_id: int

    class Config:
        from_attributes = True

# -------------------
# Role Schemas
# -------------------

class RoleBase(BaseModel):
    role_name: str

class RoleCreate(RoleBase):
    pass

class RoleResponse(RoleBase):
    role_id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True
