import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, String, Float, Integer, DateTime, Enum, Text,Boolean

from app.extension import db


class ShippingLocationMaster(db.Model):
    __tablename__ = 'shippinglocation_masters'

    shippinglocation_id  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    shippinglocation_code = Column(String,nullable=False, unique=True, index=True) 
    shippinglocation_name = Column(String, nullable=False)
    address   = Column(String, nullable=False)
    pincode = Column(String, nullable=False)
    city = Column(String, nullable=True)
    country  = Column(String, nullable=True)
    contact_person  = Column(String, nullable=False)
    contact_number  = Column(String, nullable=False)
    is_active  = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


    