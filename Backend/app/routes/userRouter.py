from flask import Blueprint, request, jsonify, request
from app.services.userServices import UserService
from app.schemas.userSchema import UserResponseSchema,UserCreateSchema,UserUpdatePutSchema,UserUpdatePatchSchema
from app.utils.mailUtils import EmailService
from app.models.userModel import User,Role
from app.extension import db
from app.utils.permissionRequired import role_required
from app.database.redis_client import add_jwt_id_to_blocklist
from app.utils.logger_config import get_logger

logger = get_logger(__name__)

from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
)

from pydantic import ValidationError
user_bp = Blueprint("user", __name__, url_prefix="/api/v1/user")


@user_bp.route('/signup', methods=['POST'])
def create_user():
    try:
        data = request.get_json()
        try:
            user_data = UserCreateSchema(**data)
        except Exception as e :
            logger.warning(f"Validation error in /signup: {e}")
            return jsonify({"error":"validation_errors"}), 422

        if UserService.user_exists(user_data.email):
            logger.info(f"Signup failed: User {user_data.email} already exists")
            return jsonify({"error": "User already exists Please Log in."}), 403  

        user = UserService.create_user(user_data)
        
        user_name = getattr(user, 'name', None) or getattr(user, 'user_name', None)

        email_result = EmailService.send_verification_email(user.email, user_name)
        user_response = UserResponseSchema.model_validate(user)
        logger.info(f"User {user.email} created successfully. Verification email sent: {email_result['success']}")

        return jsonify({
            "message": "User created. Please verify your email.",
            "user": user_response.model_dump(),
            "email_sent": email_result["success"],
            "email_error": email_result.get("message")
        }), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        logger.error(f"Internal server error in /signup: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@user_bp.route('/verify-email/<token>')
def verify_email(token):
    try:
        email = EmailService.verify_token(token)
        if not email:
            logger.warning(f"Email verification failed: Invalid or expired token {token}")
            return jsonify({"error": "Invalid or expired link"}), 400

        user = UserService.verify_user_email(email)
        if not user:
            logger.warning(f"Email verification failed: User not found for email {email}")
            return jsonify({"error": "User not found"}), 404
        
        if user.is_verified: 
            logger.info(f"Email {email} already verified")
            return jsonify({"error": "Email is already verified."}), 400
        
        user.is_verified = True
        user.is_active = True
        db.session.commit()

        EmailService.send_welcome_email(user.email, getattr(user, 'name', None) or getattr(user, 'user_name', None))
        logger.info(f"Email {email} verified successfully")
        return jsonify({"message": "Email verified successfully!"}), 200

    except Exception as e:
        logger.error(f"Internal server error in /verify-email/{token}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500

@user_bp.route('/resend-verification', methods=['POST'])
def resend_verification():
    try:
        data = request.get_json()
        email = data.get('email')

        if not email:
            logger.warning("Resend verification failed: Email missing in request")
            return jsonify({"error": "Email is required"}), 400

        user = UserService.verify_user_email(email)

        if not user:
            logger.warning(f"Resend verification failed: User {email} not found")
            return jsonify({"error": "User not found"}), 404

        if user.is_verified:
            logger.info(f"Resend verification: Email {email} already verified")
            return jsonify({"message": "Email already verified."}), 200

        email_result = EmailService.send_verification_email(user.email, getattr(user, 'name', None) or getattr(user, 'user_name', None))
        if email_result["success"]:
            logger.info(f"Verification email resent to {email}")
            return jsonify({"message": "Verification email resent!"}), 200
        else:
            logger.error(f"Failed to resend verification email to {email}: {email_result['message']}")
            return jsonify({"error": email_result["message"]}), 500

    except Exception as e:
        logger.error(f"Internal server error in /resend-verification: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@user_bp.route('/get_users', methods=['GET'])
def get_all_users():
    try:
        users = UserService.get_all_users()
        users_response = [UserResponseSchema.model_validate(user).model_dump() for user in users]
        logger.info(f"Fetched all users successfully. Count: {len(users_response)}")
        return jsonify({"users": users_response}), 200
    except Exception as e:
        logger.error(f"Internal server error in /get_users: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    
    
@user_bp.route('/get_user/<string:user_id>', methods=['GET'])
def get_a_users(user_id):
    try:
        user = UserService.get_user_by_id(user_id)
        if not user:
            logger.warning(f"Get user failed: User {user_id} not found")
            return jsonify({"error": "User not found"}), 404
        users_response = UserResponseSchema.model_validate(user).model_dump()
        logger.info(f"Fetched user {user_id} successfully")
        return jsonify({"users": users_response}), 200
    except Exception as e:
        logger.error(f"Internal server error in /get_user/{user_id}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500



@user_bp.route('/delete_user/<string:user_id>', methods=['DELETE'])
@jwt_required()
@role_required(['super_admin'])
def delete_user(user_id):
    try:
        deleted = UserService.delete_user(user_id)
        if not deleted:
            logger.warning(f"Delete user failed: User {user_id} not found")
            
            return jsonify({"error": "User not found"}), 404
        add_jwt_id_to_blocklist(user_id)
        logger.info(f"User {user_id} deleted successfully")
        return jsonify({"message": "User deleted successfully"}), 200

    except Exception as e:
        logger.error(f"Internal server error in /delete_user/{user_id}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@user_bp.route('/update_user/<string:user_id>', methods=['PUT'])
def update_user(user_id):
    try:
        data = request.get_json()
        try:
            update_data = UserUpdatePutSchema(**data)
        except Exception as e :
            logger.warning(f"Validation error in /update_user PUT: {e}")
            return jsonify({"error":"validation_errors"}), 422

        user = UserService.update_user_put(user_id, update_data)
        if not user:
            logger.warning(f"Update user PUT failed: User {user_id} not found")
            return jsonify({"error": "User not found"}), 404

        logger.info(f"User {user_id} fully updated successfully")
        return jsonify({"message": "User fully updated", "user": UserResponseSchema.model_validate(user).model_dump()}), 200
    except Exception as e:
        logger.error(f"Internal server error in /update_user PUT/{user_id}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500


@user_bp.route('/update_user/<string:user_id>', methods=['PATCH'])
def update_user_patch(user_id):
    try:
        data = request.get_json()
        try:
            update_data = UserUpdatePatchSchema(**data)
        except Exception as e:
            logger.warning(f"Validation error in /update_user PATCH: {e}")
            return jsonify({"error":"validation_errors"}), 422

        user = UserService.update_user_patch(user_id, update_data)
        if not user:
            logger.warning(f"Update user PATCH failed: User {user_id} not found")
            return jsonify({"error": "User not found"}), 404

        logger.info(f"User {user_id} partially updated successfully")
        return jsonify({"message": "User partially updated", "user": UserResponseSchema.model_validate(user).model_dump()}), 200
    except Exception as e:
        logger.error(f"Internal server error in /update_user PATCH/{user_id}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    


@user_bp.route('/delete-all-users', methods=['DELETE'])
def delete_all_users():
    try:
        users = User.query.all()
        num_deleted = len(users)

        for user in users:
            db.session.delete(user)

        db.session.commit()
        logger.info(f"Deleted all users. Count: {num_deleted}")
        return {"message": f"Deleted {num_deleted} users successfully"}, 200

    except Exception as e:
        db.session.rollback()
        logger.error(f"Internal server error in /delete-all-users: {e}", exc_info=True)
        return {"error": str(e)}, 500


@user_bp.route('/superadmin', methods=['POST'])
def create_superadmin():
    try:
        superadmin_role = Role.query.filter_by(role_name="super_admin").first()
        if not superadmin_role:
            logger.warning("Create superadmin failed: Role 'super_admin' not found")
            return jsonify({"error": "Role 'super_admin' not found. Please seed roles first."}), 404

        existing = User.query.filter_by(email="superadmin@gmail.com").first()
        if existing:
            logger.info("Superadmin already exists")
            return jsonify({"message": "Superadmin already exists."}), 200

        user = User(
            user_name="SuperAdmin",
            email="superadmin@gmail.com",
            mobile_number="9999999999",
            is_verified=True,
            is_active=True,
            role_id=superadmin_role.role_id
        )
        user.set_password("Superadmin@111")

        db.session.add(user)
        db.session.commit()
        logger.info("Superadmin created successfully")
        return jsonify({"message": "Superadmin created successfully."}), 201

    except Exception as e:
        logger.error(f"Internal server error in /superadmin: {e}", exc_info=True)
        return jsonify({"error": "Internal server error", "details": str(e)}), 500
