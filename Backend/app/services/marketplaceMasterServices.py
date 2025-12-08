from app.extension import db
from app.schemas.marketplaceMasterSchema import MarketPlaceCreate,MarketplaceMasterResponseSchema

from app.models.marketPlaceMasterModel import MarketPlaceMaster
from typing import Dict, Any
from app.utils.excellMasterHandler import ExcelMasterHandlerBase

class MarketplaceMasterServices(ExcelMasterHandlerBase):
    REQUIRED_FIELDS = [
        "marketplace_name",
        "marketplace_code",
        "website_url",
        "country",
        "currency",
        "shipping_location"
    ]

    BOOLEAN_FIELDS = ["is_active", "api_enabled"]
    UNIQUE_FIELD = ["marketplace_code"]
    MODEL = MarketPlaceMaster
    SCHEMA = MarketPlaceCreate
    STRING_FIELDS = {}

    @staticmethod
    def marketplacemaster_exist(code:str):
        marketplace_code=code.lower()
        return db.session.query(MarketPlaceMaster).filter(MarketPlaceMaster.marketplace_code == marketplace_code).first() is not None
    @staticmethod
    def get_all_marketplaces():
        marketplaces = MarketPlaceMaster.query.order_by(MarketPlaceMaster.created_at.desc()).all()
        marketplaces_masterdata = [MarketplaceMasterResponseSchema.from_orm(m).model_dump() for m in marketplaces]
        return marketplaces_masterdata

    @classmethod
    def handle_marketplace_master(cls,df) -> Dict[str, Any]:
        return cls.validate_and_process(df)
    


















    #     df.columns = df.columns.str.strip()

    #     required_columns = MarketplaceMasterServices.REQUIRED_FIELDS + MarketplaceMasterServices.BOOLEAN_FIELDS
    #     missing_cols = [col for col in required_columns if col not in df.columns]
    #     if missing_cols:
    #         return {"error": f"Missing required columns: {missing_cols}"}

    #     valid_data = []
    #     error_list = []

    #     seen_codes = set()
    #     existing_codes = {
    #         code.lower() for (code,) in db.session.query(MarketPlaceMaster.marketplace_code).all()
    #     }

    #     for index, row in df.iterrows():
    #         row_number = index + 2
    #         row_dict = row.replace({np.nan: None}).to_dict()
    #         row_errors = []

    #         for field in MarketplaceMasterServices.BOOLEAN_FIELDS:
    #             row_dict[field] = MarketplaceMasterServices.normalize_boolean(row_dict.get(field))

    #         for field in MarketplaceMasterServices.REQUIRED_FIELDS:
    #             value = row_dict.get(field)
    #             if value is None or str(value).strip() == "":
    #                 row_errors.append({"column": field, "message": f"{field} is required and cannot be empty"})

    #         code = str(row_dict.get("marketplace_code", "")).strip().lower()

    #         if not code:
    #             row_errors.append({"column": "marketplace_code", "message": "marketplace_code is required and cannot be empty"})
    #         elif code in existing_codes:
    #             row_errors.append({"column": "marketplace_code", "message": "marketplace_code already exists in database"})
    #         elif code in seen_codes:
    #             row_errors.append({"column": "marketplace_code", "message": "Duplicate marketplace_code in uploaded file"})

    #         seen_codes.add(code)

    #         try:
    #             validated = MarketPlaceCreate(**row_dict)
    #         except ValidationError as ve:
    #             for err in ve.errors():
    #                 field = err.get("loc", ["field"])[0]
    #                 msg = err.get("msg", "Invalid value")
    #                 row_errors.append({"column": field, "message": msg})

    #         if row_errors:
    #             error_list.append({
    #                 "row": row_number,
    #                 "row_data": row_dict,
    #                 "errors": row_errors
    #             })
    #         else:
    #             data_dict = validated.dict()

    #             if data_dict.get("website_url") is not None:
    #                 data_dict["website_url"] = str(data_dict["website_url"])
    #             new_entry = MarketPlaceMaster(**data_dict)
    #             db.session.add(new_entry)
    #             valid_data.append(validated.dict())
    #             existing_codes.add(code)

    #     if valid_data:
    #         db.session.commit()

    #     if error_list:
    #         return {
    #             "errors":[
    #                 {
    #                     "row": e["row"],
    #                     "invalid_data": e["row_data"],
    #                     "column_errors": e["errors"],
    #                 } for e in error_list
    #             ]
    #         }

    #     return {
    #         "status": "success",
    #         "valid_rows": len(valid_data)
    #     }

 

