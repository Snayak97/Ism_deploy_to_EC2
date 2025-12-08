from flask import Blueprint, jsonify
from app.services.shippinglocationMasterServices import ShippingLocationMasterService
from app.models.shipngLocationModel import ShippingLocationMaster
from app.extension import db


shippinglocationmaster_bp = Blueprint("shippinglocationmaster", __name__, url_prefix="/api/v1/shippinglocationmaster")




@shippinglocationmaster_bp.route('/get_shiipinglocation_masters', methods=['GET'])
def get_all_shiipinglocation_masters():
    try:
        shipping_location_masters = ShippingLocationMasterService.get_all_shippinglocations()
        return jsonify({"shiiping_location_master": shipping_location_masters}), 200
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500
    


@shippinglocationmaster_bp.route('/delete-all-shipinglocation_master', methods=['DELETE'])
def delete_shipinglocation_masters():
    try:
        num_deleted = ShippingLocationMaster.query.delete()
        db.session.commit()
        return {"message": f"Deleted {num_deleted}  shiping location master  successfully"}, 200
    except Exception as e:
        db.session.rollback()
        return {"error": str(e)}, 500