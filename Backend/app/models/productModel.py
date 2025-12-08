import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, String, Float, Integer, DateTime, Enum, Text

from app.extension import db

class ProductMaster(db.Model):
    __tablename__ = 'product_master'

    product_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    product_name = Column(String(255), nullable=False)
    sku = Column(String(100), unique=True, nullable=False)
    product_category = Column(String(100), nullable=True)
    product_attribute = Column(String(100), nullable=True)
    product_sub_attribute = Column(String(100), nullable=True)
    product_descriptions = Column(db.Text, nullable=True)
    brand = Column(String(100), nullable=True)
    price = Column(Float, nullable=True)
    moq = Column(Integer, nullable=True)  # Minimum Order Quantity
    cbm = Column(Float, nullable=True)    # Cubic Meter measurement
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<ProductMaster {self.product_name} | SKU: {self.sku}>"
    
