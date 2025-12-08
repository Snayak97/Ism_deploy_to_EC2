from flask import   jsonify
from app.models.userModel import User, Permission, RolePermission, UserPermission


from functools import wraps


from flask_jwt_extended import get_jwt_identity



def role_required(allowed_roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            identity = get_jwt_identity()
            user = User.query.get(identity)
            if not user or user.role.role_name not in allowed_roles:
                return jsonify({"error": "Permission denied"}), 403
            return fn(*args, **kwargs)
        return decorator
    return wrapper



def has_permission(user, module_name, permission_name):
    # Check role permissions (role level, no department)
    role_perm = RolePermission.query.join(Permission).filter(
        RolePermission.role_id == user.role_id,
        Permission.module_name == module_name,
        Permission.permission_name == permission_name
    ).first()
    
    if role_perm:
        return True
    
    user_department_id = user.department_id
    if user_department_id is None:
        return False

    # Check user permissions scoped by department
    user_perm = UserPermission.query.join(Permission).filter(
        UserPermission.user_id == user.user_id,
        UserPermission.department_id == user_department_id,  # add department filter here
        Permission.module_name == module_name,
        Permission.permission_name == permission_name
    ).first()

    return user_perm is not None





def permission_required(module_name, permission_name):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            user_id = get_jwt_identity()
            user = User.query.get(user_id)
            if not user:
                return jsonify({"error": "User not found"}), 404

            # Super admin shortcut - all access
            if user.role.role_name == 'super_admin':
                return fn(*args, **kwargs)

            if not has_permission(user, module_name, permission_name):
                return jsonify({"error": "Permission denied"}), 403

            return fn(*args, **kwargs)
        return wrapper
    return decorator


