# import numpy as np
# from typing import Any, Dict
# from pydantic import ValidationError
# from app.extension import db
# from app.utils.dataSerializer import serialize_for_sqlalchemy
# from pydantic import HttpUrl
# import uuid

# class ExcelMasterHandlerBase:

#     REQUIRED_FIELDS = []
#     BOOLEAN_FIELDS = []
#     STRING_FIELDS = set()      
#     UNIQUE_FIELD = None 
#     MODEL = None         
#     SCHEMA = None        

#     @classmethod
#     def normalize_boolean(cls, value: Any) -> bool:
#         """Convert various boolean-like strings/numbers to Python bool"""
#         if isinstance(value, str):
#             value = value.strip().lower()
#             if value in ["true", "yes", "1"]:
#                 return True
#             elif value in ["false", "no", "0"]:
#                 return False
#         return bool(value)

#     @classmethod
#     def validate_and_process(cls, df) -> Dict[str, Any]:
    
#         df.columns = df.columns.str.strip()


#         required_columns = cls.REQUIRED_FIELDS + cls.BOOLEAN_FIELDS
#         missing_cols = [col for col in required_columns if col not in df.columns]
#         if missing_cols:
#             return {"error": f"Missing required columns: {missing_cols}"}

#         valid_data = []
#         error_list = []

    
#         existing_codes = {
#             getattr(row, cls.UNIQUE_FIELD).lower()
#             for row in db.session.query(cls.MODEL).all()
#             if getattr(row, cls.UNIQUE_FIELD)
#         }

#         seen_codes = set()

#         for index, row in df.iterrows():
#             row_number = index + 2  
           
#             row_dict = row.replace({np.nan: None}).to_dict()
#             row_errors = []

#             for field in cls.BOOLEAN_FIELDS:
#                 row_dict[field] = cls.normalize_boolean(row_dict.get(field))

#             for field in cls.STRING_FIELDS:
#                 val = row_dict.get(field)
#                 if val is not None:
#                     row_dict[field] = str(val).strip()

      
#             for field in cls.REQUIRED_FIELDS:
#                 value = row_dict.get(field)
#                 if value is None or str(value).strip() == "":
#                     row_errors.append({
#                         "column": field,
#                         "message": f"{field} is required and cannot be empty"
#                     })

          
#             already_reported = {err["column"] for err in row_errors}

           
#             code = str(row_dict.get(cls.UNIQUE_FIELD, "")).strip().lower()
#             if not code:
#                 if cls.UNIQUE_FIELD not in already_reported:
#                     row_errors.append({
#                         "column": cls.UNIQUE_FIELD,
#                         "message": f"{cls.UNIQUE_FIELD} is required"
#                     })
#                     already_reported.add(cls.UNIQUE_FIELD)
#             elif code in existing_codes:
#                 if cls.UNIQUE_FIELD not in already_reported:
#                     row_errors.append({
#                         "column": cls.UNIQUE_FIELD,
#                         "message": "Already exists in database"
#                     })
#                     already_reported.add(cls.UNIQUE_FIELD)
#             elif code in seen_codes:
#                 if cls.UNIQUE_FIELD not in already_reported:
#                     row_errors.append({
#                         "column": cls.UNIQUE_FIELD,
#                         "message": "Duplicate in uploaded file"
#                     })
#                     already_reported.add(cls.UNIQUE_FIELD)

#             try:
#                 validated = cls.SCHEMA(**row_dict)
#             except ValidationError as ve:
#                 for err in ve.errors():
#                     field = err.get("loc", ["field"])[0]
#                     msg = err.get("msg", "Invalid value")
#                     if field not in already_reported:
#                         row_errors.append({"column": field, "message": msg})
#                         already_reported.add(field)

#             if row_errors:
#                 error_list.append({
#                     "row": row_number,
#                     "invalid_data": row_dict,
#                     "column_errors": row_errors
#                 })
#             else:
                
#                 data = serialize_for_sqlalchemy(
#                     validated.model_dump(),
#                     string_fields=cls.STRING_FIELDS,
#                     extra_type_serializers={
#                         uuid.UUID: str,
#                         HttpUrl: str,
#                     },
#                     )
#                 db.session.add(cls.MODEL(**data))
#                 valid_data.append(data)
#                 existing_codes.add(code)
#                 seen_codes.add(code)

        
#         if valid_data:
#             db.session.commit()

#         if error_list:
#             return {
#                 "errors": [
#                     {
#                         "row": e["row"],
#                         "invalid_data": e["invalid_data"],
#                         "column_errors": e["column_errors"],
#                     } for e in error_list
#                 ]
#             }

#         return {"status": "success", "valid_rows": len(valid_data), "valid_data":valid_data}



import numpy as np
from typing import Any, Dict
from pydantic import ValidationError, HttpUrl
from app.extension import db
from app.utils.dataSerializer import serialize_for_sqlalchemy
import uuid

class ExcelMasterHandlerBase:

    REQUIRED_FIELDS = []
    BOOLEAN_FIELDS = []
    STRING_FIELDS = set()
    UNIQUE_FIELD = None
    MODEL = None
    SCHEMA = None

    @classmethod
    def normalize_boolean(cls, value: Any) -> bool:
        """Convert various boolean-like strings/numbers to Python bool"""
        if isinstance(value, str):
            value = value.strip().lower()
            if value in ["true", "yes", "1"]:
                return True
            elif value in ["false", "no", "0"]:
                return False
        return bool(value)

    @classmethod
    def validate_and_process(cls, df) -> Dict[str, Any]:
        df.columns = df.columns.str.strip()

        required_columns = cls.REQUIRED_FIELDS + cls.BOOLEAN_FIELDS
        missing_cols = [col for col in required_columns if col not in df.columns]
        if missing_cols:
            return {"error": f"Missing required columns: {missing_cols}"}

        valid_data = []
        error_list = []

        unique_fields = cls.UNIQUE_FIELD if isinstance(cls.UNIQUE_FIELD, list) else [cls.UNIQUE_FIELD]

        # Existing values from DB
        existing_uniques = {
            field: {
                getattr(row, field).strip().lower()
                for row in db.session.query(cls.MODEL).all()
                if getattr(row, field)
            }
            for field in unique_fields
        }

        # Track duplicates in uploaded file
        seen_uniques = {field: set() for field in unique_fields}

        for index, row in df.iterrows():
            row_number = index + 2
            row_dict = row.replace({np.nan: None}).to_dict()
            row_errors = []

            # Normalize booleans
            for field in cls.BOOLEAN_FIELDS:
                row_dict[field] = cls.normalize_boolean(row_dict.get(field))

            # Trim string fields
            for field in cls.STRING_FIELDS:
                val = row_dict.get(field)
                if val is not None:
                    row_dict[field] = str(val).strip()

            # Required fields check
            for field in cls.REQUIRED_FIELDS:
                value = row_dict.get(field)
                if value is None or str(value).strip() == "":
                    row_errors.append({
                        "column": field,
                        "message": f"{field} is required and cannot be empty"
                    })

            already_reported = {err["column"] for err in row_errors}

            # Unique field validations
            for unique_field in unique_fields:
                value = row_dict.get(unique_field)
                value_normalized = str(value).strip().lower() if value else ""

                if not value_normalized:
                    if unique_field not in already_reported:
                        row_errors.append({
                            "column": unique_field,
                            "message": f"{unique_field} is required"
                        })
                        already_reported.add(unique_field)
                elif value_normalized in existing_uniques.get(unique_field, set()):
                    if unique_field not in already_reported:
                        row_errors.append({
                            "column": unique_field,
                            "message": "Already exists in database"
                        })
                        already_reported.add(unique_field)
                elif value_normalized in seen_uniques[unique_field]:
                    if unique_field not in already_reported:
                        row_errors.append({
                            "column": unique_field,
                            "message": "Duplicate in uploaded file"
                        })
                        already_reported.add(unique_field)

            # Pydantic schema validation
            try:
                validated = cls.SCHEMA(**row_dict)
            except ValidationError as ve:
                for err in ve.errors():
                    field = err.get("loc", ["field"])[0]
                    msg = err.get("msg", "Invalid value")
                    if field not in already_reported:
                        row_errors.append({"column": field, "message": msg})
                        already_reported.add(field)

            if row_errors:
                error_list.append({
                    "row": row_number,
                    "invalid_data": row_dict,
                    "column_errors": row_errors
                })
            else:
                data = serialize_for_sqlalchemy(
                    validated.model_dump(),
                    string_fields=cls.STRING_FIELDS,
                    extra_type_serializers={
                        uuid.UUID: str,
                        HttpUrl: str,
                    },
                )
                db.session.add(cls.MODEL(**data))
                valid_data.append(data)

                # Update seen + existing
                for field in unique_fields:
                    val = row_dict.get(field)
                    if val:
                        normalized_val = str(val).strip().lower()
                        seen_uniques[field].add(normalized_val)
                        existing_uniques[field].add(normalized_val)

        if valid_data:
            db.session.commit()

        # if error_list:
        #     return {
        #         "errors": [
        #             {
        #                 "row": e["row"],
        #                 "invalid_data": e["invalid_data"],
        #                 "column_errors": e["column_errors"],
        #             } for e in error_list
        #         ]
        #     }

        # return {"status": "success", "valid_rows": len(valid_data), "valid_data": valid_data}
        response = {
        "status": "partial_success" if error_list and valid_data else "success",
        "valid_rows": len(valid_data),
        "valid_data": valid_data,
            }

        if error_list:
            response["errors"] = [
                {
                "row": e["row"],
                "invalid_data": e["invalid_data"],
                 "column_errors": e["column_errors"],
                } for e in error_list
            ]

        # If all rows failed (valid_data is empty)
        if not valid_data and error_list:
            response["status"] = "error"  # or "failed"

        return response
