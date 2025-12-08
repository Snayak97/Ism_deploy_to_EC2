import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, String, Float, Integer, DateTime, Enum, Text,Boolean

from app.extension import db


class MarketPlaceMaster(db.Model):
    __tablename__ = 'marketplace_masters'

    marketplace_id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    marketplace_name = Column(String, nullable=False)
    marketplace_code = Column(String,nullable=False, unique=True, index=True) 
    website_url  = Column(String, nullable=False)
    country = Column(String, nullable=False)
    currency = Column(Float, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    api_enabled = Column(Boolean, nullable=False, default=False)
    shipping_location =Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self):
        return f"<marketplace_masters {self.marketplace_name}>"
    