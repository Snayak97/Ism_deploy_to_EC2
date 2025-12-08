from flask import Blueprint, request, jsonify
from app.models.userModel import User, Role, Permission, RolePermission, ScopeEnum,UserPermission,Department,Client
from app.extension import db
from sqlalchemy.exc import IntegrityError

from app.utils.permissionRequired import role_required, permission_required
from app.services.permissionServices import Permissions_services

from flask_jwt_extended import get_jwt_identity,jwt_required

permission_bp = Blueprint("permission", __name__, url_prefix="/api/v1/permission")








@permission_bp.route('/assign-role-permissions', methods=['POST'])
def assign_role_permissions():
    try:
        roles = {
            "super_admin": {
                "scope": ScopeEnum.all,
                "permissions": "all"  # means assign all permissions
            },
            "client_admin": {
                "scope": ScopeEnum.own_org,
                "permissions": "all"
            },
            "manager": {
                "scope": ScopeEnum.own_org,
                "permissions":[]
            },
            "employee": {
                "scope": ScopeEnum.own_org,
                "permissions": []  # limited permissions
            },
            "normal_user": {
                "scope": ScopeEnum.own_org,
                "permissions": []  # only product view permission
            }
        }

        messages = []

        for role_name, details in roles.items():
            role = Role.query.filter_by(role_name=role_name).first()
            if not role:
                messages.append(f"❌ Role {role_name} not found, skipping")
                continue

            scope = details["scope"]
            perms_to_assign = details["permissions"]

            if perms_to_assign == "all":
                # Assign all permissions available
                all_permissions = Permission.query.all()
                for perm in all_permissions:
                    # Check if already assigned
                    existing = RolePermission.query.filter_by(role_id=role.role_id, permission_id=perm.permission_id).first()
                    if not existing:
                        rp = RolePermission(role_id=role.role_id, permission_id=perm.permission_id, scope=scope)
                        db.session.add(rp)
                messages.append(f"✅ Assigned ALL permissions with scope '{scope.name}' to {role_name}")

            elif isinstance(perms_to_assign, list):
                # Assign specific permissions
                for perm_data in perms_to_assign:
                    if isinstance(perm_data, tuple):
                        module_name, permission_name = perm_data
                    else:
                        module_name = None
                        permission_name = perm_data

                    query = Permission.query
                    if module_name:
                        query = query.filter_by(module_name=module_name)
                    if permission_name:
                        query = query.filter_by(permission_name=permission_name)
                    perm = query.first()

                    if not perm:
                        messages.append(f"❌ Permission {module_name}/{permission_name} not found")
                        continue

                    existing = RolePermission.query.filter_by(role_id=role.role_id, permission_id=perm.permission_id).first()
                    if not existing:
                        rp = RolePermission(role_id=role.role_id, permission_id=perm.permission_id, scope=scope)
                        db.session.add(rp)

                messages.append(f"✅ Assigned limited permissions to {role_name}")

        db.session.commit()

        return jsonify({
            "status": "success",
            "message": "Role permissions assigned successfully.",
            "details": messages
        }), 201

    except IntegrityError as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Database error", "details": str(e)}), 500

    except Exception as e:
        db.session.rollback()
        return jsonify({"status": "error", "message": "Unexpected error", "details": str(e)}), 500




@permission_bp.route('/create-permissions', methods=['POST'])
def seed_permissions():
    modules = [
        "Product",
        "User",
        "Department",
        "Invoice",
        "Order"
    ]
    permission_types = ["View", "Create", "Edit", "Delete"]

    messages = []

    for module in modules:
        for perm in permission_types:
            existing = Permission.query.filter_by(module_name=module, permission_name=perm).first()
            if not existing:
                new_permission = Permission(module_name=module, permission_name=perm)
                db.session.add(new_permission)
                messages.append(f"✅ Created: {module} - {perm}")
            else:
                messages.append(f"ℹ️ Already exists: {module} - {perm}")

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Permissions seeding complete.",
        "details": messages
    }), 201


@permission_bp.route('/create-role', methods=['POST'])
def seed_roles():
    roles = [
        "super_admin",
        "client_admin",
        "manager",
        "employee",
        "normal_user"
    ]

    messages = []

    for role_name in roles:
        existing = Role.query.filter_by(role_name=role_name).first()
        if not existing:
            new_role = Role(role_name=role_name)
            db.session.add(new_role)
            messages.append(f"✅ Created role: {role_name}")
        else:
            messages.append(f"ℹ️ Role already exists: {role_name}")

    db.session.commit()

    return jsonify({
        "status": "success",
        "message": "Role seeding complete.",
        "details": messages
    }), 201



# client admin
@permission_bp.route("/assign-user-permissions", methods=["POST"])
@jwt_required()
@role_required(["client_admin"])
def assign_user_permissions():
   
    try:
        data = request.get_json()
        user_id = data.get("user_id")
        permissions = data.get("permissions") 

        client_admin_id = get_jwt_identity()

        result, status_code = Permissions_services.assign_user_permissions(client_admin_id, user_id, permissions)
        return jsonify(result), status_code
    except Exception as e:
        print(e)
        return jsonify({"error":"internal server errors"}),500



# @permission_bp.route('/assign-user-permissions', methods=['POST'])
# @jwt_required()
# @role_required(['client_admin'])
# def assign_user_permissions():
#     data = request.get_json()
#     user_id = data.get('user_id')
#     permissions = data.get('permissions')  # list of dicts [{"module_name":..., "permission_name":...}]

#     if not user_id or permissions is None:
#         return jsonify({"error": "user_id and permissions are required"}), 400

#     user = User.query.get(user_id)
#     if not user:
#         return jsonify({"error": "User not found"}), 404

#     client_admin = User.query.get(get_jwt_identity())
#     if user.client_id != client_admin.client_id:
#         return jsonify({"error": "You can assign permissions only to users in your client organization"}), 403

#     try:
#         # Remove existing permissions for this user and their department
#         UserPermission.query.filter_by(user_id=user_id, department_id=user.department_id).delete()

#         for perm_data in permissions:
#             module_name = perm_data.get('module_name')
#             permission_name = perm_data.get('permission_name')
#             if not module_name or not permission_name:
#                 continue

#             perm = Permission.query.filter_by(module_name=module_name, permission_name=permission_name).first()
#             if perm:
#                 user_perm = UserPermission(
#                     user_id=user_id,
#                     permission_id=perm.permission_id,
#                     department_id=user.department_id
#                 )
#                 db.session.add(user_perm)

#         db.session.commit()

#         return jsonify({
#             "status": "success",
#             "message": f"Permissions assigned to user successfully. Total permissions assigned: {len(permissions)}"
#         })

#     except IntegrityError as e:
#         db.session.rollback()
#         return jsonify({"error": "Database integrity error", "details": str(e)}), 500
#     except Exception as e:
#         db.session.rollback()
#         return jsonify({"error": "Unexpected error", "details": str(e)}), 500


@permission_bp.route('/all-permissions', methods=['GET'])
@jwt_required()
@role_required(['client_admin'])
def get_all_permissions():
    permissions = Permission.query.all()
    data = [
        {
            "permission_id": str(p.permission_id),
            "module_name": p.module_name,
            "permission_name": p.permission_name
        }
        for p in permissions
    ]
    return jsonify({"status": "success", "permissions": data}), 200






@permission_bp.route('/user-permissions/<string:user_id>', methods=['GET'])
@jwt_required()
@role_required(['client_admin'])
def get_user_permissions(user_id):
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    client_admin = User.query.get(get_jwt_identity())
    if user.client_id != client_admin.client_id:
        return jsonify({"error": "Forbidden"}), 403

    permissions = (
        UserPermission.query
        .filter_by(user_id=user_id, department_id=user.department_id)
        .join(Permission, UserPermission.permission_id == Permission.permission_id)
        .all()
    )

    result = [
        {
            "module_name": up.permission.module_name,
            "permission_name": up.permission.permission_name
        }
        for up in permissions
    ]

    return jsonify({
        "status": "success",
        "user": user.email,
        "permissions": result
    }), 200




@permission_bp.route('/orders/create', methods=['POST'])
@jwt_required()
@permission_required('Order', 'Create')
def create_order():
    data = request.json
    # Your order creation logic here
    return jsonify({"message": "Order created successfully", "order": data}), 201


