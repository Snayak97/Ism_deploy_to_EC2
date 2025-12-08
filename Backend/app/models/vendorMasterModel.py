import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, String, Float, Integer, DateTime, Enum, Text,Boolean

from app.extension import db


# class VendorMaster(db.Model):
#     __tablename__ = 'vendor_masters'

#     vendor_id  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
#     vendor_code = Column(String,nullable=False, unique=True, index=True) 
#     vendor_name = Column(String, nullable=False)
#     vendor_type = Column(String, nullable=False)
#     country  = Column(String, nullable=True)
#     currency = Column(Float, nullable=True)
#     sales_channel_url   = Column(String, nullable=False)
#     is_active  = Column(Boolean, nullable=False, default=False)
#     api_enabled = Column(Boolean, nullable=False, default=False)
#     created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
#     updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

