from flask import Blueprint, request, jsonify, send_file
import pandas as pd
from urllib.parse import unquote
from urllib.parse import quote
import os
from app.extension import db
from app.models.marketPlaceMasterModel import MarketPlaceMaster
from app.services.marketplaceMasterServices import MarketplaceMasterServices
from app.services.shippinglocationMasterServices import ShippingLocationMasterService
from app.services.sellingPlatformMasterServices import SellingPlatformMasterService
from app.services.platformMasterServices import PlatformMasterService
from app.utils.errorExcell import  write_errors_to_excel
from flask_jwt_extended import (
    jwt_required,

)

marketplacemaster_bp = Blueprint("marketplacemaster", __name__, url_prefix="/api/v1/marketplacemaster")



@marketplacemaster_bp.route("/upload_master_data", methods=["POST"])

def masterdata_upload():
    try:
        if 'file' not in request.files:
            return jsonify({"error": "Excel file not provided."}), 400

        file = request.files['file']

        if not file.filename.endswith((".xls", ".xlsx")):
            return jsonify({"error": "Invalid file format. Only .xls or .xlsx files are allowed."}), 400

        xls = pd.ExcelFile(file)

        sheet_handlers = {
            "marketplace_master": MarketplaceMasterServices.handle_marketplace_master,
            "shipping_location": ShippingLocationMasterService.handle_shippinglocation_master,
            "selling_platform": SellingPlatformMasterService.handle_selling_platform_master,
            "platform_master": PlatformMasterService.handle_platform_master,
        }

        results = {}
        errors = {}
        error_sheets = {}
      

        for sheet_name, handler in sheet_handlers.items():
            if sheet_name not in xls.sheet_names:
                errors[sheet_name] = f"Sheet '{sheet_name}' not found in Excel file."
                continue

            df = xls.parse(sheet_name)
            result = handler(df)

            # if isinstance(result, dict) and "errors" in result:
            #     errors[sheet_name] = result["errors"]
            #     error_sheets[sheet_name] = result["errors"]
            # else:
            #     results[sheet_name] = result
            if result.get("status") == "error":
                errors[sheet_name] = result["errors"]
                error_sheets[sheet_name] = result["errors"]
            elif result.get("status") == "partial_success":
                results[sheet_name] = {
                    "status": "partial_success",
                    "valid_rows": result["valid_rows"],
                    "valid_data": result["valid_data"],
                    }
                errors[sheet_name] = result["errors"]
                error_sheets[sheet_name] = result["errors"]
            else:
                results[sheet_name] = {
                "status": "success",
                "valid_rows": result["valid_rows"],
                "valid_data": result["valid_data"],
                }


    

        error_file_name = None
        if error_sheets:
            error_file_name = write_errors_to_excel(error_sheets, original_filename=file.filename)
            encoded_file = quote(error_file_name) if error_file_name else None
        else:
            encoded_file = None

        # response_data = {
        #     "marketplaces": MarketplaceMasterServices.get_all_marketplaces(),
        #     "shipping_locations": ShippingLocationMasterService.get_all_shippinglocations(),
        #     "selling_platforms" : SellingPlatformMasterService.get_all_selling_platforms(),
        #     "platforms_masters" : PlatformMasterService.get_all_platforms(),
        # }


        response = {
            "processing_results": results,
            "processing_errors": errors if errors else None,
            "data": "",
            "error_file_url": f"/api/v1/marketplacemaster/download_error_file?filename={encoded_file}" if encoded_file else None,
        }

        return jsonify(response), 207 if errors else 200

    except Exception as e:
        print(e)
        return jsonify({"error": f"Internal server error: {str(e)}"}), 500




@marketplacemaster_bp.route("/download_error_file", methods=["GET"])
def download_error_file():

    try:
        file_name = request.args.get("filename")
        if not file_name:
         return jsonify({"error": "Filename is required"}), 400
        
        file_name = unquote(file_name)  

        if ".." in file_name or file_name.startswith(("/", "\\")):
            return jsonify({"error": "Invalid filename"}), 400

        # Rebuild full path based on secure uploads directory
        base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
        errors_dir = os.path.join(base_dir, "uploads", "errors")
        full_path = os.path.join(errors_dir, file_name)

        if not os.path.exists(full_path):
            return jsonify({"error": "File not found"}), 404

        return send_file(full_path, as_attachment=True, download_name=file_name)
    except Exception as e:
        print(e)
        return jsonify({"error": "Internal server error"}), 500


@marketplacemaster_bp.route('/get_marketplace_masters', methods=['GET'])

def get_all_Marketplace_masters():
    try:
        Marketplace_masters = MarketplaceMasterServices.get_all_marketplaces()
        return jsonify({"marketplace_masters": Marketplace_masters}), 200
    except Exception as e:
        print("error",e)
        return jsonify({"error": "Internal server error"}), 500

@marketplacemaster_bp.route('/delete-all-marketplace_master', methods=['DELETE'])

def delete_marketplace_masters():
    try:
        num_deleted = MarketPlaceMaster.query.delete()
        db.session.commit()
        return {"message": f"Deleted {num_deleted}  marketplace master  successfully"}, 200
    except Exception as e:
        db.session.rollback()
        return {"error": str(e)}, 500
    