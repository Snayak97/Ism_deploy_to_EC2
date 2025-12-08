from app.extension import db
from app.schemas.sellingPlatformMasterSchema  import SellingPlatformCreate,SellingPlatformResponseSchema

from app.models.sellingPlatformMasterModel import SellingPlatformMaster
from typing import Dict, Any
from app.utils.excellMasterHandler import ExcelMasterHandlerBase

class SellingPlatformMasterService(ExcelMasterHandlerBase):

    REQUIRED_FIELDS = [
        "selling_platform_name",
        "selling_platform_type",
        "country",
        "currency",
        "sales_channel_url",
        "is_active",
        "api_enabled",

    ]
    BOOLEAN_FIELDS = ["is_active","api_enabled"]
    UNIQUE_FIELD = ["selling_platform_name"]
    MODEL = SellingPlatformMaster
    SCHEMA = SellingPlatformCreate
    STRING_FIELDS = set()

    @staticmethod
    def selling_platform_exist(selling_platform_name: str) -> bool:
        selling_platform_name_lower = selling_platform_name.lower()
        return db.session.query(SellingPlatformMaster).filter(
            SellingPlatformMaster.selling_platform_name == selling_platform_name_lower
        ).first() is not None

    @staticmethod
    def get_all_selling_platforms():
        locations = SellingPlatformMaster.query.order_by(SellingPlatformMaster.created_at.desc()).all()
        return [SellingPlatformResponseSchema.from_orm(loc).model_dump() for loc in locations]

    
    @classmethod
    def handle_selling_platform_master(cls,df) -> Dict[str, Any]:
        return cls.validate_and_process(df)



    
    