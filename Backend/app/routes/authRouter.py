from flask import Blueprint, request, jsonify, current_app
from app.services.authServices import AuthService
from app.services.userServices import UserService
from app.utils.permissionRequired import role_required
from app.schemas.userSchema import UserLoginSchema,UserResponseSchema,ChangePasswordSchema,ForgotPasswordRequest,ResetPasswordRequest
from app.extension import db
import time
from app.utils.logger_config import get_logger
logger = get_logger(__name__)

from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    create_access_token,
    create_refresh_token,
    get_jwt,
)
from app.database.redis_client import add_jwt_id_to_blocklist


auth_bp = Blueprint("auth", __name__, url_prefix="/api/v1/auth")


@auth_bp.route('/login', methods=['POST'])
def login_user():
    start_time = time.time() 
    endpoint = '/login'
    try:
        data = request.get_json()
        try:
            login_data = UserLoginSchema(**data)
        except Exception as e :
            logger.warning(f"Validation error in {endpoint}: {e}")
            return jsonify({"error":"validation_errors"}), 422
   

        if not UserService.user_exists(login_data.email):
            current_app.login_failed.inc()
            logger.info(f"Login failed: user {login_data.email} does not exist")
            return jsonify({"error": "User does not exists"}), 404  

        user, tokens = AuthService.user_login(login_data)
        if not user:
            current_app.login_failed.inc()
            logger.info(f"Login failed: Invalid credentials for {login_data.email}")
            return jsonify({"error": "Invalid email or password"}), 401
        
        if not user.is_active:
            current_app.login_failed.inc()
            logger.info(f"Login failed: Inactive account {login_data.email}")
            return jsonify({"error": "User account is inactive. Please contact support."}), 403
        if not user.is_verified:
            current_app.login_failed.inc()
            logger.info(f"Login failed: Email not verified {login_data.email}")
            return jsonify({"error": "Please verify your email before logging in."}), 403
        
        user.update_last_active()
        db.session.commit() 
        logger.info(f"User {login_data.email} logged in successfully")
        
        role_name = user.role.role_name if user.role else "unknown"
        login_type = {
            "super_admin": "Super Admin ",
            "client_admin": "Client Admin ",
            "manager": "Manager",
            "employee": "Employee",
            "normal_user": "Normal User "
        }.get(role_name, "Unknown Role ")
        

        user_response = UserResponseSchema.model_validate(user)
        user_data = user_response.model_dump()


        user_data["role_name"] = user.role.role_name if user.role else None
        user_data["department_name"] = user.department.department_name if user.department else None
        current_app.login_success.inc()
        try:
            if user.user_id not in current_app.logged_in_users_set:
                current_app.logged_in_users_set.add(user.user_id)
                current_app.logged_in_users.inc()
        except Exception as e:
            print("Error updating logged_in_users:", e)

        return jsonify({
            "message": f"{login_type} Logged in successfully!",
            "user": user_data,
            "access_token": tokens["access_token"],
            "refresh_token": tokens["refresh_token"],
            "force_reset_password": user.must_reset_password or False
        }), 200

    except Exception as e:
        logger.error(f"Internal server error in {endpoint}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    
    finally:
        # Record request latency
        current_app.request_latency.labels(endpoint='/login').observe(time.time() - start_time)
    

@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout_user():
    start_time = time.time() 
    endpoint = '/logout'
    try:
        jwt_payload = get_jwt()
        jti = jwt_payload.get("jti")
        user_id = get_jwt_identity()

        if not jti:
            logger.warning(f"Logout failed: Invalid token for user {user_id}")
            return jsonify({"error": "Invalid token"}), 400

        add_jwt_id_to_blocklist(jti)

        current_app.logout_total.inc()
        
        try:
            if user_id in current_app.logged_in_users_set:
                current_app.logged_in_users_set.remove(user_id)

                current_app.logged_in_users.set(
                len(current_app.logged_in_users_set)
                )
                logger.info(f"User {user_id} logged out successfully")

                
        except Exception as e:
            print("Error updating logged_in_users:", e)

        return jsonify({"message": "Successfully logged out"}), 200

    except Exception as e:
        logger.error(f"Internal server error in {endpoint}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    
    finally:
        current_app.request_latency.labels(endpoint='/logout').observe(time.time() - start_time)
    

@auth_bp.post("/refresh_access_token")
@jwt_required(refresh=True)
def refresh_access():
    endpoint = '/refresh_access_token'
    try:
        identity = get_jwt_identity()
        jwt_payload = get_jwt()
        refresh_jti = jwt_payload["jti"]

  
        add_jwt_id_to_blocklist(refresh_jti)

        new_access_token = create_access_token(identity=identity)
        new_refresh_token = create_refresh_token(identity=identity)
        logger.info(f"Access token refreshed for user {identity}")
        return jsonify({
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "message": "Access token refreshed successfully"
        }), 200

    except  Exception as e:
        logger.error(f"Token refresh failed in {endpoint}: {e}", exc_info=True)
        return jsonify({"error": "Token refresh failed"}), 500


@auth_bp.route('/profile', methods=['GET'])
@jwt_required()
def user_profile():
    user_id = get_jwt_identity()  # Get user identifier stored in the token
    # Now do something with user_id, e.g. fetch user data from DB
    return jsonify({"message": f"Hello user {user_id}, you are logged in!"}), 200


@auth_bp.route('/change_password', methods=['POST'])
@jwt_required()
def password_change():
    endpoint = '/change_password'
    
    try:
        data = request.get_json()
        

        try:
            change_data = ChangePasswordSchema(**data)
            
        except Exception as e:
            logger.warning(f"Validation error in {endpoint}: {e} | Data: {data}")
            return jsonify({"error":"validation_errors"}), 422

        
        if change_data.new_password != change_data.confirm_password:
            logger.info(f"Password change failed: Passwords do not match for user {get_jwt_identity()}")
            return jsonify({"error": "Passwords do not match"}), 400
        
        if change_data.old_password == change_data.new_password:
            logger.info(f"Password change failed: Old password same as new password for user {get_jwt_identity()}")
            return jsonify({"error": "New password must be different from old password"}), 400
    
        user_id = get_jwt_identity()

 
        success, message = AuthService.change_user_password(
            user_id=user_id,
            old_password=change_data.old_password,
            new_password=change_data.new_password
        )
       

        if not success:
            logger.info(f"Password change failed for user {user_id}: {message}")
            return jsonify({"error": message}), 400
        logger.info(f"Password changed successfully for user {user_id}")
        return jsonify({"message": message}), 200

    except Exception as e:
        logger.error(f"Internal server error in {endpoint}: {e}", exc_info=True)
        return jsonify({"error": "Internal Server Error"}), 500
    

@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    
    try:
        data = request.get_json()
        try:
            request_data = ForgotPasswordRequest(**data)
        except Exception as e:
            logger.warning(f"Validation error in /forgot-password: {e}")
            return jsonify({"error":"validation_errors"}), 422
   

        response = AuthService.handle_forgot_password(request_data.email)
        if "error" in response:
            logger.info(f"Forgot password failed for {request_data.email}")
            return jsonify(response), 400
        
        logger.info(f"Forgot password requested for {request_data.email}")
        return jsonify(response), 200

    except Exception as e :
        logger.error(f"Internal server error in /forgot-password: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json()
        try:
            request_data = ResetPasswordRequest(**data)
        except Exception as e:
            logger.warning(f"Validation error in /reset-password: {e}")
            return jsonify({"error":"validation_errors"}), 422

        response = AuthService.handle_reset_password(request_data.token, request_data.new_password)

        if "error" in response:
            logger.info(f"Reset password failed for token {request_data.token}")
            return jsonify(response), 400
        
        logger.info(f"Password reset successful for token {request_data.token}")
        return jsonify(response), 200

    except Exception as e:
        logger.error(f"Internal server error in /reset-password: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    




@auth_bp.route('/deactivate_user/<string:user_id>', methods=['POST'])
@jwt_required()
@role_required(['super_admin','client_admin'])
def deactivate_user_route(user_id):
    try:
        user = UserService.get_user_by_id(user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404
        if not user.is_active:
            return jsonify({"error": "User already Deactivated"}), 400

        if AuthService.deactivate_user(user):
            add_jwt_id_to_blocklist(user_id)
            logger.info(f"User {user_id} deactivated by {get_jwt_identity()}")
            return jsonify({"message": "User deactivated successfully"}), 200

    except Exception as e:
        logger.error(f"Internal server error in /deactivate_user/{user_id}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    

@auth_bp.route('/activate_user/<string:user_id>', methods=['POST'])
@jwt_required()
@role_required(['super_admin','client_admin'])
def activate_user_route(user_id):
    try:
        user = UserService.get_user_by_id(user_id)
        if not user:
            return jsonify({"error": "User not found"}), 404
        if user.is_active:
            return jsonify({"error": "User already activated"}), 400

        if AuthService.activate_user(user):
            logger.info(f"User {user_id} activated by {get_jwt_identity()}")
            return jsonify({"message": "User activated successfully"}), 200

    except Exception as e:
        logger.error(f"Internal server error in /activate_user/{user_id}: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500



@auth_bp.route('/all_clients_and_normal_users', methods=['GET'])
@jwt_required()
@role_required(['super_admin'])
def all_clients_and_normal_users():
    try:
        data = UserService.get_all_clients_with_users_and_normal_users()
        logger.info(f"All clients and normal users fetched by {get_jwt_identity()}")
        return jsonify({
            "status": "success",
            "data": data
        }), 200
    except Exception as e:
        logger.error(f"Internal server error in /all_clients_and_normal_users: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500
    

@auth_bp.route('/all_clientsadmin_and_normal_users', methods=['GET'])
@jwt_required()
@role_required(['super_admin'])
def all_clients_admin_and_normal_users():
    try:
        data = UserService.get_all_clientadmins_and_normal_users()
        logger.info(f"All client admins and normal users fetched by {get_jwt_identity()}")
        return jsonify({
            "status": "success",
            "data": data
        }), 200
    except Exception as e:
        logger.error(f"Internal server error in /all_clientsadmin_and_normal_users: {e}", exc_info=True)
        return jsonify({"error": "Internal server error"}), 500