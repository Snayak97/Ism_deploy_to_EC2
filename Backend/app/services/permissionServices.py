from app.models.userModel import User,Permission,UserPermission
from app.extension import db

from sqlalchemy.exc import IntegrityError

class Permissions_services:
    @staticmethod
    def assign_user_permissions(client_admin_id, user_id, permissions):
        if not user_id or not permissions:
            return {"error": "user_id and permissions are required"}, 400

        user = User.query.get(user_id)
        if not user:
            return {"error": "User not found"}, 404

        client_admin = User.query.get(client_admin_id)
        if not client_admin:
            return {"error": "Client admin user not found"}, 404

        if user.client_id != client_admin.client_id:
            return {"error": "You can assign permissions only to users in your client organization"}, 403

        try:
            # Remove existing permissions for this user in their department
            UserPermission.query.filter_by(
                user_id=user_id,
                department_id=user.department_id
            ).delete()

            for perm_data in permissions:
                module_name = perm_data.get("module_name")
                permission_name = perm_data.get("permission_name")

                if not module_name or not permission_name:
                    continue

                perm = Permission.query.filter_by(
                    module_name=module_name,
                    permission_name=permission_name
                ).first()

                if perm:
                    new_user_perm = UserPermission(
                        user_id=user_id,
                        permission_id=perm.permission_id,
                        department_id=user.department_id
                    )
                    db.session.add(new_user_perm)

            db.session.commit()

            return {
                "status": "success",
                "message": f"Permissions assigned to user successfully. Total permissions assigned: {len(permissions)}"
            }, 200

        except IntegrityError as e:
            db.session.rollback()
            return {"error": "Database integrity error", "details": str(e)}, 500

        except Exception as e:
            db.session.rollback()
            return {"error": "Unexpected error", "details": str(e)}, 500
        
        