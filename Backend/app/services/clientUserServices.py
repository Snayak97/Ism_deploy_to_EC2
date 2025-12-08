from app.models.userModel import User,Role,Department,UserPermission
from app.extension import db
from app.utils.genPassword import generate_random_password
from app.utils.mailUtils import EmailService
from flask import current_app
from app.services.userServices import UserService

class ClientUserService:

    # check same department manager is exist or not
    @staticmethod
    def manager_exist_in_department(department_id):
   
        manager_role = Role.query.filter_by(role_name="manager").first()
        if not manager_role:
            raise ValueError("Manager role not found.")

   
        existing_manager = User.query.filter_by(
            department_id=department_id,
            role_id=manager_role.role_id
            ).first()
        return existing_manager is not None
    
    # @staticmethod
    # def get_or_create_department(client_id, department_name, created_by_user_id, role_name=None):
    #     if not department_name:
    #         raise ValueError("Department name is required.")
    #     department = Department.query.filter_by(
    #         client_id=client_id,
    #         department_name=department_name.lower()
    #     ).first()
    #     if department:
    #         if role_name and role_name.lower() == "manager":
    #             if ClientUserService.manager_exist_in_department(department.department_id):
    #                 raise ValueError(
    #                     f"Department '{department_name}' already has a manager for this client."
    #                 )
    #         return department

    #     department = Department(
    #         department_name=department_name.lower(),
    #         client_id=client_id,
    #         created_by_user_id=created_by_user_id
    #     )
    #     db.session.add(department)
    #     db.session.commit()
    #     return department
    
    @staticmethod
    def get_or_create_department(client_id, department_name, created_by_user_id, role_name=None):
        if not department_name:
            raise ValueError("Department name is required.")
        
        role_name = role_name.lower() if role_name else None

        department = Department.query.filter_by(
            client_id=client_id,
            department_name=department_name.lower()
        ).first()
        if department:
            if role_name and role_name.lower() == "manager":
                if ClientUserService.manager_exist_in_department(department.department_id):
                    raise ValueError(
                        f"Department '{department_name}' already has a manager for this client."
                    )
            else:
                if not ClientUserService.manager_exist_in_department(department.department_id):
                    raise ValueError(
                        f"Cannot create '{role_name}' in department '{department_name}' because no manager exists."
                        )
   
            return department

        department = Department(
            department_name=department_name.lower(),
            client_id=client_id,
            created_by_user_id=created_by_user_id
        )
        db.session.add(department)
        db.session.commit()

        if role_name and role_name.lower() != "manager":
            raise ValueError(
                f"Cannot create '{role_name}' in new department '{department_name}' without a manager."
                )
        return department
    
    
    

    @staticmethod
    def create_client_user_services(data, created_by_user):
        role_name= data.role_name.lower()
        role = Role.query.filter_by(role_name=role_name).first()
        if not role:
            raise ValueError("Role 'client_user' not found. Please seed roles.")

   
        if User.query.filter_by(email=data.email.lower()).first():
            raise ValueError("User with this email already exists.")

        department = ClientUserService.get_or_create_department(
            client_id=created_by_user.client_id,
            department_name=data.department_name,
            created_by_user_id=created_by_user.user_id,
            role_name=role_name
        )

     
        default_password = generate_random_password()

        new_user = User(
            user_name=data.user_name,
            email=data.email.lower(),
            mobile_number=data.mobile_number,
            role_id=role.role_id,
            client_id=created_by_user.client_id,
            department_id=department.department_id,
            created_by_user_id=created_by_user.user_id,
            is_verified=True,
            is_active=True,
            must_reset_password=True
        )
        new_user.set_password(default_password)

        db.session.add(new_user)
        db.session.commit()

        # Send login credentials to email
        frontend_url = current_app.config.get("FRONTEND_URL", "http://localhost:3000")
        login_url = f"{frontend_url}/signin"

        EmailService.send_account_created_email(
            user_email=new_user.email,
            user_name=new_user.user_name,
            role=new_user.role_name,
            temp_password=default_password,
            login_url=login_url
        )

        return new_user


    @staticmethod
    def update_client_user_service(user, data):
        if data.user_name:
            user.user_name = data.user_name

        if data.email:
            existing_user = User.query.filter(
                User.email == data.email.lower(),
                User.user_id != user.user_id
            ).first()
            if existing_user:
                raise ValueError("Email already exists.")
            user.email = data.email.lower()

        if data.mobile_number:
            user.mobile_number = data.mobile_number

        if data.role_name:
            role = Role.query.filter_by(role_name=data.role_name.lower()).first()
            if not role:
                raise ValueError(f"Role '{data.role_name}' not found.")
            user.role_id = role.role_id

        if data.department_name:
            department = ClientUserService.get_or_create_department(
                client_id=user.client_id,
                department_name=data.department_name,
                created_by_user_id=user.created_by_user_id
            )
            user.department_id = department.department_id

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

        return user

    @staticmethod
    def delete_client_user_service(user_id, current_admin):
        user_to_delete = UserService.get_user_by_id(user_id)

        if not user_to_delete:
            raise ValueError("Client User not found.")
        
        if user_to_delete.user_id == current_admin.user_id:
            raise ValueError("You cannot delete yourself.")

        if user_to_delete.client_id != current_admin.client_id:
            raise ValueError("Unauthorized to delete this user.")

        try:
            UserPermission.query.filter_by(user_id=user_to_delete.user_id).delete()
            db.session.delete(user_to_delete)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

        return f"Client User '{user_to_delete.user_name}' deleted successfully."
    
