from flask import Blueprint, jsonify
from app.extension import db
from app.models.sellingPlatformMasterModel import SellingPlatformMaster
from app.services.sellingPlatformMasterServices import SellingPlatformMasterService


sellingplatformmaster_bp = Blueprint("sellingplatformmaster", __name__, url_prefix="/api/v1/sellingplatformmaster")


@sellingplatformmaster_bp.route('/get_sellingplatform_masters', methods=['GET'])
def get_all_sellingplatform_masters():
    try:
        selling_platform_masters = SellingPlatformMasterService.get_all_selling_platforms()
        return jsonify({"selling_platform_masters": selling_platform_masters}), 200
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500


@sellingplatformmaster_bp.route('/delete-all-sellingplatform_master', methods=['DELETE'])
def delete_sellingplatform_masters():
    try:
        num_deleted = SellingPlatformMaster.query.delete()
        db.session.commit()
        return {"message": f"Deleted {num_deleted}  selling platform master  successfully"}, 200
    except Exception as e:
        db.session.rollback()
        return {"error": str(e)}, 500