from flask import Blueprint, jsonify
from app.services.platformMasterServices import PlatformMasterService
from app.models.platformMasterModel import PlatformMaster
from app.extension import db


platformmaster_bp = Blueprint("platformmaster", __name__, url_prefix="/api/v1/platformmaster")



@platformmaster_bp.route('/get_platform_masters', methods=['GET'])

def get_all_platform_masters():
    try:
        platform_masters = PlatformMasterService.get_all_platforms()
        return jsonify({"platform_master": platform_masters}), 200
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500
    


@platformmaster_bp.route('/delete-all-platform_master', methods=['DELETE'])

def delete_platform_masters():
    try:
        num_deleted = PlatformMaster.query.delete()
        db.session.commit()
        return {"message": f"Deleted {num_deleted}  platform master  successfully"}, 200
    except Exception as e:
        db.session.rollback()
        return {"error": str(e)}, 500