import pandas as pd
import tempfile
import os
from datetime import datetime


def write_errors_to_excel(error_sheets: dict, original_filename: str, save_dir: str = "uploads/errors") -> str:
    #Get project root dynamically
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))  
    full_save_dir = os.path.join(base_dir, save_dir)

    #Create directory if not exists
    os.makedirs(full_save_dir, exist_ok=True)

    #Generate file name with timestamp
    base_name = os.path.splitext(original_filename)[0]
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    file_name = f"{base_name}_errors_{timestamp}.xlsx"

    #Final full path
    full_path = os.path.join(full_save_dir, file_name)

    with pd.ExcelWriter(full_path, engine='openpyxl') as writer:
        for sheet_name, errors in error_sheets.items():
            rows = []
            for err in errors:
                row_data = err["invalid_data"]
                row_number = err["row"]
                error_messages = "; ".join(
                    [f"{e['column']}: {e['message']}" for e in err["column_errors"]]
                )
                formatted_row = {
                    "Errors": error_messages,
                    "Row Number": row_number,
                    **row_data
                }
                rows.append(formatted_row)

            df = pd.DataFrame(rows)
            df.to_excel(writer, sheet_name=sheet_name[:31], index=False)

  
    return file_name
