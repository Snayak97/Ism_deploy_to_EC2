from app.extension import db
from app.schemas.shippinglocationMasterSchema  import ShippingLocationCreateSchema,ShippingLocationMasterResponseSchema

from app.models.shipngLocationModel import ShippingLocationMaster
from typing import Dict, Any
from app.utils.excellMasterHandler import ExcelMasterHandlerBase

class ShippingLocationMasterService(ExcelMasterHandlerBase):

    REQUIRED_FIELDS = [
        "shippinglocation_code",
        "shippinglocation_name",
        "address",
        "pincode",
        "contact_person",
        "contact_number"
    ]
    BOOLEAN_FIELDS = ["is_active"]
    UNIQUE_FIELD = ["shippinglocation_code"]
    MODEL = ShippingLocationMaster
    SCHEMA = ShippingLocationCreateSchema
    STRING_FIELDS = {"pincode", "contact_number"}

    @staticmethod
    def shippinglocation_exist(code: str) -> bool:
        code_lower = code.lower()
        return db.session.query(ShippingLocationMaster).filter(
            ShippingLocationMaster.shippinglocation_code == code_lower
        ).first() is not None

    @staticmethod
    def get_all_shippinglocations():
        locations = ShippingLocationMaster.query.order_by(ShippingLocationMaster.created_at.desc()).all()
        return [ShippingLocationMasterResponseSchema.from_orm(loc).model_dump() for loc in locations]

    
    @classmethod
    def handle_shippinglocation_master(cls,df) -> Dict[str, Any]:
        return cls.validate_and_process(df)
    