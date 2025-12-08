from app.models.userModel import User,Role,Client,UserPermission,Department
from app.extension import db
from app.utils.genPassword import generate_random_password
from app.utils.mailUtils import EmailService
from flask import current_app
from app.services.userServices import UserService
from app.database.redis_client import add_jwt_id_to_blocklist


class ClientService:

    @staticmethod
    def create_client_admin(data, created_by_user_id):
        clientadmin_role = Role.query.filter_by(role_name="client_admin").first()
        if not clientadmin_role:
            return None
        client = Client(
            org_name=data.org_name.lower(),
            org_email=data.org_email.lower(),
            created_by_user_id=created_by_user_id
        )
        default_password=generate_random_password()
        user = User(
            user_name=data.user_name,
            email=data.email.lower(),
            mobile_number=data.mobile_number,
            role_id=clientadmin_role.role_id,
            client=client,  
            is_verified=True,
            is_active=True,
            created_by_user_id=created_by_user_id,
            must_reset_password= True
        )
        user.set_password(default_password)

        db.session.add_all([client, user])
        db.session.commit()

        frontend_url = current_app.config.get('FRONTEND_URL', 'http://localhost:3000')
        login_link = f"{frontend_url}/signin"

        EmailService.send_account_created_email(user_email=user.email, user_name=user.user_name, role=user.role_name, temp_password=default_password, login_url=login_link)

        return user
    

    @staticmethod
    def update_client_admin_details(user_id, update_data):
        user = UserService.get_user_by_id(user_id)

        if not user or user.role.role_name != "client_admin":
           return None

        if update_data.user_name:
            user.user_name = update_data.user_name
        if update_data.email:
            user.email = update_data.email.lower()
        if update_data.mobile_number:
            user.mobile_number = update_data.mobile_number

        if user.client:
            if update_data.org_name:
                user.client.org_name = update_data.org_name.lower()
            if update_data.org_email:
                user.client.org_email = update_data.org_email.lower()

        db.session.commit()
        
        return user
    


    @staticmethod
    def delete_client_admin_service(user_id):
        user = UserService.get_user_by_id(user_id)
        if not user:
            raise ValueError("Client Admin not found")

        if user.role.role_name != "client_admin":
            raise ValueError("User is not a Client Admin")
    
        try:
      
            client_id = user.client.client_id if user.client else None

        
            if client_id:
                departments = Department.query.filter_by(client_id=client_id).all()
                for dept in departments:
                    dept_users = User.query.filter_by(department_id=dept.department_id).all()
                    for dept_user in dept_users:
                        UserPermission.query.filter_by(user_id=dept_user.user_id).delete()
                        db.session.delete(dept_user)
                    db.session.delete(dept)

            client_users = User.query.filter_by(created_by_user_id=user.user_id).all()
            for client_user in client_users:
                UserPermission.query.filter_by(user_id=client_user.user_id).delete()
                db.session.delete(client_user)

        
            if user.client:
                db.session.delete(user.client)

        
            UserPermission.query.filter_by(user_id=user.user_id).delete()
            db.session.delete(user)

            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

        return f"Client Admin '{user.user_name}' and their client organization (with departments & users) have been deleted successfully."






