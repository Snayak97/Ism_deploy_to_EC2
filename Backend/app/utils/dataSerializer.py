from datetime import datetime
from typing import Any,Dict,Optional,Set,Type
import pytz
IST = pytz.timezone("Asia/Kolkata")


def serialize_for_sqlalchemy(
    data: Dict[str, Any],
    string_fields: Optional[Set[str]] = None,
    extra_type_serializers: Optional[Dict[Type, callable]] = None,
    datetime_format: str = "%d-%m-%Y %H:%M:%S",
) -> Dict[str, Any]:
    if string_fields is None:
        string_fields = set()  
    if extra_type_serializers is None:
        extra_type_serializers = {}

    def serialize_value(key: str, value: Any):
        if key in string_fields and value is not None:
            return str(value).strip()

        for typ, serializer in extra_type_serializers.items():
            if isinstance(value, typ):
                return serializer(value)

        if isinstance(value, datetime):
            return value.strftime(datetime_format)

        return value

    return {k: serialize_value(k, v) for k, v in data.items()}

