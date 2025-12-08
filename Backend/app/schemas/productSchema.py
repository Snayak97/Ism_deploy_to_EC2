from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from uuid import UUID
from datetime import datetime

class ProductCreateSchema(BaseModel):
    product_name: str
    sku: str
    product_category: Optional[str] = None
    product_attribute: Optional[str] = None
    product_sub_attribute: Optional[str] = None
    product_descriptions: Optional[str] = None
    brand: Optional[str] = None
    price: Optional[float] = None
    moq: Optional[int] = None
    cbm: Optional[float] = None


class ProductResponseSchema(BaseModel):
    product_id: UUID
    product_name: str
    sku: str
    product_category: Optional[str]
    product_attribute: Optional[str]
    product_sub_attribute: Optional[str]
    product_descriptions: Optional[str]
    brand: Optional[str]
    price: Optional[float]
    moq: Optional[int]
    cbm: Optional[float]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class ProductUpdatePutSchema(BaseModel):
    product_name: str
    sku: str
    product_category: Optional[str] = None
    product_attribute: Optional[str] = None
    product_sub_attribute: Optional[str] = None
    product_descriptions: Optional[str] = None
    brand: Optional[str] = None
    price: Optional[float] = None
    moq: Optional[int] = None
    cbm: Optional[float] = None


class ProductUpdatePatchSchema(BaseModel):
    product_name: Optional[str] = None
    sku: Optional[str] = None
    product_category: Optional[str] = None
    product_attribute: Optional[str] = None
    product_sub_attribute: Optional[str] = None
    product_descriptions: Optional[str] = None
    brand: Optional[str] = None
    price: Optional[float] = None
    moq: Optional[int] = None
    cbm: Optional[float] = None
