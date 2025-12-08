from app.extension import db
from app.schemas.platformMasterSchema import PlatformMasterCreate,PlatformMasterResponseSchema

from app.models.platformMasterModel import PlatformMaster
from typing import Dict, Any
from app.utils.excellMasterHandler import ExcelMasterHandlerBase

class PlatformMasterService(ExcelMasterHandlerBase):

    REQUIRED_FIELDS = [
        "platform_name",
        "description",
        "email",
        "address"
    ]
    BOOLEAN_FIELDS = []
    UNIQUE_FIELD = ["platform_name","email"]
    MODEL = PlatformMaster
    SCHEMA = PlatformMasterCreate
    STRING_FIELDS = set()

    @staticmethod
    def platform_exist(selling_platform_name: str) -> bool:
        platform_name_lower = selling_platform_name.lower()
        return db.session.query(PlatformMaster).filter(
            PlatformMaster.platform_name == platform_name_lower
        ).first() is not None

    @staticmethod
    def get_all_platforms():
        locations = PlatformMaster.query.order_by(PlatformMaster.created_at.desc()).all()
        return [PlatformMasterResponseSchema.from_orm(loc).model_dump() for loc in locations]

    
    @classmethod
    def handle_platform_master(cls,df) -> Dict[str, Any]:
        return cls.validate_and_process(df)



    
    