from flask import Blueprint, request, jsonify, request
from app.services.clientUserServices import ClientUserService
from app.services.userServices import UserService
from app.schemas.clientSchema import ClientUserCreateSchema,ClientResponseSchema,ClientUserUpdateSchema
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.schemas.userSchema import UserResponseSchema
from app.utils.permissionRequired import role_required
from app.models.userModel import User,Role,Department
from app.database.redis_client import add_jwt_id_to_blocklist

client_user_bp = Blueprint("client_user", __name__, url_prefix="/api/v1/client_user")

# client admin access
@client_user_bp.route('/create_client_user', methods=['POST'])
@jwt_required()
@role_required(["client_admin"])
def client_user_create():
    try:
        data = request.get_json()
        client_user_id = get_jwt_identity()
        client_admin_user = UserService.get_user_by_id(client_user_id)

        if not client_admin_user:
            return jsonify({"error":" User not found"}),404
        try:
            client_user_data = ClientUserCreateSchema(**data)
        except Exception as e :

            return jsonify({"error":"validation_errors"}), 422
        
        if UserService.user_exists(client_user_data.email):
            return jsonify({"error": "User already exists Please Log in."}), 403 
        new_client_user = ClientUserService.create_client_user_services(client_user_data, created_by_user=client_admin_user)
        
        new_client_user_response = UserResponseSchema.model_validate(new_client_user).model_dump()
        return jsonify({
            "message": "Client User created successfully",
            "user": new_client_user_response
        }), 201
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        print(e)
        return jsonify({"error": "Internal server error"}), 500
    


@client_user_bp.route('/update_client_user/<string:user_id>', methods=['PUT'])
@jwt_required()
@role_required(["client_admin"])
def update_client_user(user_id):
    try:
        current_user_id = get_jwt_identity()
        current_admin = UserService.get_user_by_id(current_user_id)
        if not current_admin:
            return jsonify({"error": "Admin user not found"}), 404

     
        user_to_update = UserService.get_user_by_id(user_id)
        if not user_to_update:
            return jsonify({"error": "Client user not found"}), 404

        if user_to_update.client_id != current_admin.client_id:
            return jsonify({"error": "Unauthorized"}), 403

        data = request.get_json()

        try:
            update_data = ClientUserUpdateSchema(**data)
        except Exception as e:
            return jsonify({"error": "Validation error", "details": str(e)}), 422

        updated_user = ClientUserService.update_client_user_service(user_to_update, update_data)
        add_jwt_id_to_blocklist(user_id)
        
        user_response = UserResponseSchema.model_validate(updated_user).model_dump()

        return jsonify({
            "message": "Client user updated successfully",
            "user": user_response
        }), 200
    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404

    except Exception as e:
        print(e)
        return jsonify({"error": "Internal server error"}), 500


# client admin  access and delete single users;
@client_user_bp.route("/delete_client_user/<string:user_id>",methods=["DELETE"])
@jwt_required()
@role_required(["client_admin"])
def client_user_delete(user_id):
    try:
        current_user_id = get_jwt_identity()
        current_user = UserService.get_user_by_id(current_user_id)

        if not current_user:
            return jsonify({"error": "User not found"}), 404
        add_jwt_id_to_blocklist(user_id)
        message = ClientUserService.delete_client_user_service(user_id,current_user)

        return jsonify({"message": message}), 200

    except ValueError as ve:
        return jsonify({"error": str(ve)}), 404
    
    except Exception as e:
        print(e)
        return jsonify({"error": "Internal server error"}), 500
    
# client admin can delete multiple client users
@client_user_bp.route("/delete_client_users", methods=["DELETE"])
@jwt_required()
@role_required(["client_admin"])
def delete_multiple_client_users():
    try:
        current_user_id = get_jwt_identity()
        current_user = UserService.get_user_by_id(current_user_id)

        if not current_user:
            return jsonify({"error": "User not found"}), 404

        data = request.get_json()
        user_ids = data.get("user_ids", [])
        
        if not user_ids or not isinstance(user_ids, list):
            return jsonify({"error": "Invalid or missing 'user_ids' list"}), 400

        messages = []
        for user_id in user_ids:
            try:
                msg = ClientUserService.delete_client_user_service(user_id, current_user)
                messages.append({"user_id": user_id, "status": "deleted", "message": msg})
            except ValueError as ve:
                messages.append({"user_id": user_id, "status": "error", "message": str(ve)})
            except Exception as e:
                messages.append({"user_id": user_id, "status": "error", "message": "Internal server error"})

        return jsonify({
            "message": "Bulk delete operation completed.",
            "results": messages
        }), 200

    except Exception as e:
        return jsonify({"error": "Internal server error"}), 500





@client_user_bp.route('/list_client_users', methods=['GET'])
@jwt_required()
@role_required(["client_admin"])
def list_client_users():
    try:
        current_user_id = get_jwt_identity()
        client_admin_user = UserService.get_user_by_id(current_user_id)
        if not client_admin_user:
            return jsonify({"error": "User not found"}), 404

        
        client_admin_role = Role.query.filter_by(role_name="client_admin").first()
        if not client_admin_role:
            return jsonify({"error": "Role 'client_admin' not found"}), 500

        query = User.query.filter(
            User.client_id == client_admin_user.client_id,
            User.role_id != client_admin_role.role_id
        )

       
        role_name = request.args.get("role", type=str)
        department_name = request.args.get("department", type=str)

        if role_name:
            role = Role.query.filter_by(role_name=role_name.lower()).first()
            if role:
                query = query.filter(User.role_id == role.role_id)
            else:
                return jsonify({"error": f"Role '{role_name}' not found"}), 404

        if department_name:
            department = Department.query.filter_by(
                client_id=client_admin_user.client_id,
                department_name=department_name.lower()
            ).first()
            if department:
                query = query.filter(User.department_id == department.department_id)
            else:
                return jsonify({"error": f"Department '{department_name}' not found"}), 404

        # Pagination (optional)
        page = request.args.get("page", default=1, type=int)
        per_page = request.args.get("per_page", default=20, type=int)
        pagination = query.paginate(page=page, per_page=per_page, error_out=False)
        users = pagination.items

        client_data = ClientResponseSchema.model_validate(client_admin_user.client).model_dump()
        users_response = [UserResponseSchema.model_validate(user).model_dump() for user in users]

        return jsonify({
            "message": "Client users fetched successfully",
            "client_data": client_data,
            "users": users_response,
            "pagination": {
                "page": page,
                "per_page": per_page,
                "total_pages": pagination.pages,
                "total_items": pagination.total,
            }
        }), 200

    except Exception as e:
        print("Error in list_client_users:", e)
        return jsonify({"error": "Internal server error"}), 500







# @client_user_bp.route('/list_client_users', methods=['GET'])
# @jwt_required()
# @role_required(["client_admin"])
# def list_client_users():
#     try:
#         current_user_id = get_jwt_identity()
#         client_admin_user = UserService.get_user_by_id(current_user_id)

#         if not client_admin_user:
#             return jsonify({"error": "User not found"}), 404
        
#         client_admin_role = Role.query.filter_by(role_name="client_admin").first()
        
#         client_id = client_admin_user.client_id
 
#         client_users = User.query.filter(
#                             User.client_id == client_id,
#                             User.role_id != client_admin_role.role_id
#                         ).all()
#         client_data = ClientResponseSchema.model_validate(client_admin_user.client).model_dump()
        
#         users_response = [UserResponseSchema.model_validate(user).model_dump() for user in client_users]

#         return jsonify({
#             "message": "Client users fetched successfully",
#             "client_data":client_data,
#             "users": users_response
#         }), 200

#     except Exception as e:
#         return jsonify({"error": "Internal server error"}), 500

