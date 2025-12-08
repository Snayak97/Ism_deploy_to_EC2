from app.models.userModel import User
from flask_jwt_extended import create_access_token, create_refresh_token,decode_token
from app.config import Config
from app.extension import db
from app.utils.mailUtils import EmailService
from flask import current_app




class AuthService:

    @staticmethod
    def user_login(login_data):
        email = login_data.email.strip().lower()
        user = User.query.filter_by(email=email).first()

        if not user or not user.check_password(login_data.password):
            return False,""
        
        access_token = create_access_token(
            identity=str(user.user_id),
            expires_delta=Config.JWT_ACCESS_TOKEN_EXPIRES
        )
        refresh_token = create_refresh_token(
            identity=str(user.user_id),
            expires_delta=Config.JWT_REFRESH_TOKEN_EXPIRES
        )
        reset_token = create_access_token(
                identity=str(user.user_id),
                expires_delta=Config.JWT_RESET_EXPIRY,
                additional_claims={"type": "password_reset"}
            )
        
        tokens = {
            "access_token": "",
            "refresh_token": "",
        }
        if user.must_reset_password:
            tokens["access_token"]=reset_token
        else:
            tokens["access_token"]=access_token
            tokens["refresh_token"]=refresh_token
        
        return user, tokens
    

    @staticmethod
    def change_user_password(user_id: str, old_password: str, new_password: str) -> tuple:
        user = User.query.get(user_id)
       

        if not user:
            return False, "User not found"

        if not user.check_password(old_password):
            return False, "Old password is incorrect"
     

        user.set_password(new_password)
        db.session.commit()

        return True, "Password changed successfully"
    

    @staticmethod
    def handle_forgot_password(email: str):
        email= email.strip().lower()
        user = User.query.filter_by(email=email).first()

        if not user :
            return {"error": "User Not Found"}

        token = create_access_token(
                identity=str(user.user_id),
                expires_delta=Config.JWT_RESET_EXPIRY,
                additional_claims={"type": "password_reset"}
            )
        frontend_url = current_app.config.get('FRONTEND_URL', 'http://localhost:3000')
        reset_link = f"{frontend_url}/forgot-password-verify/{token}"
        EmailService.send_password_reset_email(user.email, reset_link,user.user_name)

        return {"message": "If this email exists, a reset link was sent."}
    
    

    @staticmethod
    def handle_reset_password(token: str, new_password: str):
        try:
            decoded = decode_token(token)

            if decoded.get('type') != 'password_reset':
                raise Exception("Invalid token type")

            user_id = decoded.get('sub')
   
            if not user_id:
                return {"error": "Invalid token structure."}
            user = User.query.get(user_id)
            if not user:
                raise Exception("User not found")
            
            user.set_password(new_password)
            user.must_reset_password = False
            db.session.commit()
            EmailService.send_password_reset_success_email(user.email, getattr(user, 'name', None) or getattr(user, 'user_name', None))
            return {"message": "Password updated successfully."}

        except Exception as e:
            return {"error": str(e)}
        


    @staticmethod
    def deactivate_user(user: User) -> bool:
        user.deactivate()
        db.session.commit()
        return True

    @staticmethod
    def activate_user(user: User) -> bool:
        user.activate()
        db.session.commit()
        return True