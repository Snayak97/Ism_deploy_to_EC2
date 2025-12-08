from flask import request, jsonify,current_app,after_this_request
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity
from app.models.userModel import User


def active_user_check():
    # Skip preflight requests
    if request.method == "OPTIONS":
        return None




    # Verify JWT for other requests
    verify_jwt_in_request(optional=False)
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)

    if not user or not user.is_active:
        return jsonify({"error": "Account deactivated"}), 401

    if user.role in ["manager","employee"]:
        client_admin = User.query.filter_by(
            role="client_admin",
            client_id=user.client_id
        ).first()
        if not client_admin or not client_admin.is_active:
            return jsonify({"error": "Client Admin deactivated"}), 401

    return None
