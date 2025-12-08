from app.models.userModel import User,Role,Client
from app.extension import db
from app.schemas.userSchema import UserResponseSchema



class UserService:
    
    #  get exist user
    @staticmethod
    def user_exists(email: str) -> bool:
        email=email.lower()
        return db.session.query(User).filter(User.email == email).first() is not None
    
    # veryfy email
    @staticmethod
    def verify_user_email(email: str) -> bool:
        email=email.lower()
        return db.session.query(User).filter(User.email == email).first() 

    # create user
    @staticmethod
    def create_user(user_data: dict) -> User:
        user_role = Role.query.filter_by(role_name='normal_user').first()
        if not user_role:
             raise ValueError("Default role 'user' not found. Please seed roles..")

        user = User(
            user_name=user_data.user_name,
            email=user_data.email.lower(),
            mobile_number=user_data.mobile_number,
            role_id=user_role.role_id
        )
       

        user.set_password(user_data.password)
        try:
            db.session.add(user)
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            raise e

        return user
    

    # get all users
    @staticmethod
    def get_all_users():
        return db.session.query(User).all()
    
    # single user
    @staticmethod
    def get_user_by_id(user_id: str):
        return db.session.query(User).filter(User.user_id == user_id).first()

    # delete user
    @staticmethod
    def delete_user(user_id):
        user = UserService.get_user_by_id(user_id)
        if not user:
            return False
        db.session.delete(user)
        db.session.commit()
        return True
    
    
    # updateUser
    @staticmethod
    def update_user_put(user_id: str, update_data):
        user = UserService.get_user_by_id(user_id)
        if not user:
            return None

        if update_data.user_name is not None:
            user.user_name = update_data.user_name
        if update_data.email is not None:
            user.email = update_data.email.lower()
        if update_data.mobile_number is not None:
            user.mobile_number = update_data.mobile_number
    

        db.session.commit()
        return user

    # updateUser
    @staticmethod
    def update_user_patch(user_id: str, update_data):
        user = UserService.get_user_by_id(user_id)
        if not user:
            return None

        for field, value in update_data.dict(exclude_unset=True).items():
            setattr(user, field, value)

        db.session.commit()
        return user

    @staticmethod
    def get_all_clients_with_users_and_normal_users():
        clients = Client.query.all()
        result = []

        for client in clients:
            users = User.query.filter_by(client_id=client.client_id).all()
            users_data = [UserResponseSchema.model_validate(u).model_dump() for u in users]

            client_data = {
                "client_id": client.client_id,
                "org_name": client.org_name,
                "org_email": client.org_email,
                "users": users_data,
                "total_users": len(users_data)
            }
            result.append(client_data)
           

   
        # normal_users = User.query.filter_by(client_id=None).all()
        normal_users = User.query.join(Role).filter(
            User.client_id.is_(None),
            Role.role_name == 'normal_user'
                ).all()
        normal_users_data = [UserResponseSchema.model_validate(u).model_dump() for u in normal_users]

        return {
            "clients": result,
            "normal_users": normal_users_data,
            "total_normal_users": len(normal_users_data),
        }


    @staticmethod
    def get_all_clientadmins_and_normal_users():
        clients = Client.query.all()
        result = []

        for client in clients:
            # Fetch client admins for each client
            client_admins = User.query.join(Role).filter(
                User.client_id == client.client_id,
             Role.role_name == "client_admin"
            ).all()
            client_admins_data = [UserResponseSchema.model_validate(u).model_dump() for u in client_admins]

            client_data = {
                "client_id": client.client_id,
                "org_name": client.org_name,
                "org_email": client.org_email,
                "client_admins": client_admins_data,
                "total_client_admins": len(client_admins_data)
            }
            result.append(client_data)

    # Fetch all normal users without client
        normal_users = User.query.join(Role).filter(
            User.client_id.is_(None),
            Role.role_name == "normal_user"
        ).all()
        normal_users_data = [UserResponseSchema.model_validate(u).model_dump() for u in normal_users]

        return {
            "clients": result,
            "normal_users": normal_users_data,
            "total_normal_users": len(normal_users_data),
        }
