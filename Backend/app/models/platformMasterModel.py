import uuid
from datetime import datetime
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import Column, String, Float, Integer, DateTime, Enum, Text,Boolean

from app.extension import db


class PlatformMaster(db.Model):
    __tablename__ = 'platform_masters'

    platform_id  = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4, nullable=False)
    platform_name = Column(String,nullable=False, unique=True, index=True) 
    description = Column(String, nullable=False)
    email  = Column(String, nullable=False , unique=True)
    address = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
