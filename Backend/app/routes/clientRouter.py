from flask import Blueprint, request, jsonify, request

from app.services.clientServices import ClientService
from app.services.userServices import UserService
from app.schemas.clientSchema import ClientAdminCreateSchema,ClientResponseSchema,ClientAdminResponseSchema,ClientAdminUpdateSchema
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.schemas.userSchema import UserResponseSchema
from app.utils.permissionRequired import role_required
from app.database.redis_client import add_jwt_id_to_blocklist

client_bp = Blueprint("client", __name__, url_prefix="/api/v1/client")


# super admin access
@client_bp.route('/client_admin', methods=['POST'])
@jwt_required()
@role_required(["super_admin"])
def create_clientAdmin():
    try:
        current_user_id = get_jwt_identity()
        data = request.get_json()
        try:
            
            client_admin_data = ClientAdminCreateSchema(**data)
        except :
            return jsonify({"error":"validation_errors"}), 422

        if UserService.user_exists(client_admin_data.email):
            return jsonify({"error": "client_admin already exists Please Log in."}), 403  

        new_client_admin = ClientService.create_client_admin(client_admin_data,current_user_id)
        if not new_client_admin:
            return jsonify({"error": "Role 'clientadmin' not found. Please seed roles."}), 400
        
        client_admin_response = ClientResponseSchema.from_orm(new_client_admin.client)
       

        return jsonify({
            "message": "client_admin created. login credentials and link is sent your email Please login.",
            "user": client_admin_response.dict(),
        }), 201

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500



# # super admin access
@client_bp.route("/super_admin_get_client_admin_details/<string:user_id>",methods=["GET"])
@jwt_required()
@role_required(["super_admin"])
def get_client_admin_details(user_id):
    try:
        user = UserService.get_user_by_id(user_id)

        if not user:
            return jsonify({"error": "User not found"}), 404
        
        if user.role.role_name != "client_admin":
            return jsonify({"error":"User is not a client_admin"}), 403
        
        if not user.client:
            return jsonify({"error": "Client not found for this user"}), 404
        
        user_data = UserResponseSchema.model_validate(user)
        client_data = ClientResponseSchema.model_validate(user.client)

        client_admin_data = ClientAdminResponseSchema(user=user_data, client=client_data)

        return jsonify({"client_admin": client_admin_data.model_dump()}), 200

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500
    


# superadmin can access
@client_bp.route("/super_admin_update_client_admin/<string:user_id>", methods=["PUT"])
@jwt_required()
@role_required(["super_admin"])
def update_client_admin(user_id):
    try:
    
        data = request.get_json()
        try:
            update_data = ClientAdminUpdateSchema(**data)
        except :
            return jsonify({"error":"validation_errors"}), 422
        
        updated_user = ClientService.update_client_admin_details(user_id, update_data)

        if not updated_user:
            return jsonify({"error":"Client Admin not found"}), 404
        add_jwt_id_to_blocklist(user_id)
        return jsonify({
            "message": "Client Admin updated successfully",
            "user": UserResponseSchema.model_validate(updated_user).model_dump()
        }), 200
    
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500
      
       

# # super admin access
@client_bp.route("/delete_client_admin/<string:user_id>",methods=["DELETE"])
@jwt_required()
@role_required(["super_admin"])
def client_admin_delete(user_id):
    try:  
        message = ClientService.delete_client_admin_service(user_id)
        add_jwt_id_to_blocklist(user_id)
        return jsonify({"message": message}), 200

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404
    
    except Exception as e:
        print(e)
        return jsonify({"error": "Internal server error"}), 500

            


# client admin access
@client_bp.route("/client_admin_detail",methods=["GET"])
@jwt_required()
@role_required(["client_admin"])
def get_won_client_admin_details():
    try:
        current_user_id = get_jwt_identity()
        current_user = UserService.get_user_by_id(current_user_id)

        if not current_user:
            return jsonify({"error": "User not found"}), 404
        
        if current_user.role.role_name != "client_admin":
            return jsonify({"error":"Only client_admin can access this route"}), 403
        
        if not current_user.client:
            return jsonify({"error": "Client not found for this user"}), 404
        
        user_data = UserResponseSchema.from_orm(current_user)
        client_data = ClientResponseSchema.from_orm(current_user.client)

        client_admin_data = ClientAdminResponseSchema(user=user_data, client=client_data)

        return jsonify({"client_admin": client_admin_data.model_dump()}), 200

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500
    




#client admin access
@client_bp.route("/client_admin_update_me", methods=["PUT"])
@jwt_required()
@role_required(["client_admin"])
def update_own_client_admin():
    try:
        data = request.get_json()
        current_user_id = get_jwt_identity()

        try:
            update_data = ClientAdminUpdateSchema(**data)
        except :
            return jsonify({"error":"validation_errors"}), 422
        
        updated_user = ClientService.update_client_admin_details(current_user_id, update_data)

        if not updated_user:
            return jsonify({"error":"Client Admin not found"}), 404

        return jsonify({
            "message": "Client Admin updated successfully",
            "user": UserResponseSchema.from_orm(updated_user).dict()
        }), 200
    
    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500
    
    