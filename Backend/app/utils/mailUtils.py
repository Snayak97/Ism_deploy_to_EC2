import threading
from flask import current_app, url_for
from flask_mail import Message
from app.extension import mail
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from app.config import Config
# import logging

# logger = logging.getLogger(__name__)


class EmailService:

    @staticmethod
    def get_serializer():
        return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

    @staticmethod
    def generate_verification_token(email: str) -> str:
        """Generate a secure verification token"""
        serializer = EmailService.get_serializer()
        return serializer.dumps(email, salt=current_app.config.get('EMAIL_VERIFICATION_SALT', 'email-verification'))

    @staticmethod
    def verify_token(token: str, expiration: int = 3600):
        """Verify the token and return email if valid"""
        serializer = EmailService.get_serializer()
        try:
            return serializer.loads(
                token,
                salt=current_app.config.get('EMAIL_VERIFICATION_SALT', 'email-verification'),
                max_age=expiration
            )
        # except SignatureExpired:
        #     logger.warning("Token expired.")
        # except BadSignature:
        #     logger.warning("Invalid token signature.")
        # except Exception as e:
        #     logger.exception("Token verification failed.")
        except Exception as e:
            print(e)

        return None
    
    @staticmethod
    def send_async_email(app, msg):
        with app.app_context():
            mail.send(msg)

    @staticmethod
    def send_email(subject, recipients, body, html_body):
        """Central email sending method"""
        try:
            msg = Message(
                subject=subject,
                recipients=recipients,
                body=body,
                html=html_body,
                sender=current_app.config.get('MAIL_DEFAULT_SENDER', current_app.config.get('MAIL_USERNAME'))
            )
            thread = threading.Thread(target=EmailService.send_async_email, args=(current_app._get_current_object(), msg))
            thread.start()
            return {"success": True}
        except Exception as e:
            return {"success": False, "message": str(e)}

    @staticmethod
    def send_verification_email(user_email, user_name=None):
        """Send verification email to user"""
        token = EmailService.generate_verification_token(user_email)
        frontend_url = current_app.config.get('FRONTEND_URL', 'http://localhost:3000')
        verify_url = f"{frontend_url}/verify-email/{token}"
        # verify_url = url_for('user.verify_email', token=token, _external=True)

        subject = "Verify Your Email Address"
        body = f"""
        Hello {user_name or 'User'},

        Thank you for signing up! Please verify your email address by clicking the link below:
        {verify_url}

        This link will expire in 1 hour.
        If you didn't create an account, please ignore this email.

        Best regards,
        Your App Team
        """

        html_body = f"""
        <div style="font-family: Arial; max-width: 600px; margin: auto;">
            <h2>Welcome to Accurest</h2>
            <p>Hello {user_name or 'User'},</p>
            <p>Please verify your email:</p>
            <a href="{verify_url}" style="padding:10px 20px;background:#007bff;color:#fff;border-radius:4px;text-decoration:none; margin: 0 3px;">
                Verify Email
            </a>
            <p>This link will expire in 1 hour.</p>
            <p>The Accurest Team</p>
            <p><a href="https://accurest.co/" style="color:#0000FF;font-weight: bold; text-decoration: underline;">[Accurest.co]</a></p>
        </div>
        """

        return EmailService.send_email(subject, [user_email], body, html_body)

    @staticmethod
    def send_welcome_email(user_email, user_name=None):
        
        subject = "Welcome to Accurest – Your Account is Verified! 🎉"

        body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; color: #333;">
        
        Hello {user_name or 'User'},

        Your email has been successfully verified. You can now log in and start using all the features of Accurest.

        We're excited to have you with us!

        Best regards,  
        The Accurest Team
        """

        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; color: #333;">
        <h1 style="color: #2c3e50;">Welcome to Accurest</h1>
        <h2 style="color: #27ae60;">Your Account Has Been Verified 🎉</h2>
        <p>Hi {user_name or 'User'},</p>
        <p>We're excited to let you know that your account has been successfully verified.</p>
        <p>You can now log in and start using all the features Accurest has to offer.</p>
        <p style="margin-top: 30px;">Welcome aboard!</p>
        <p>The Accurest Team</p>
        <p><a href="https://accurest.co/" style="color:#0000FF;font-weight: bold; text-decoration: underline;">[Accurest.co]</a></p>
        </div>
        """

        return EmailService.send_email(subject, [user_email], body, html_body)
    
    @staticmethod
    def send_password_reset_email(user_email, reset_url, user_name=None):
        """Send password reset email with reset link"""

        subject = "Reset Your Password – Accurest"

        body = f"""
        Hello {user_name or 'User'},

        We received a request to reset your password. Click the link below to choose a new one:
        {reset_url}

        This link will expire in 15 minutes.
        If you didn’t request a password reset, you can ignore this email.

        Best regards,  
        The Accurest Team
        """

        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px;">
            <h2 style="color: #e67e22;">Password Reset Request</h2>
            <p>Hello {user_name or 'User'},</p>
            <p>We received a request to reset your password. Click the button below to set a new one:</p>
            <a href="{reset_url}" style="padding: 10px 20px; background-color: #e67e22; color: white; text-decoration: none; border-radius: 5px;">Reset Password</a>
            <p>This link will expire in 10 minutes.</p>
            <p>If you didn’t request a password reset, please ignore this email.</p>
            <p style="margin-top: 30px;">The Accurest Team</p>
            <p><a href="https://accurest.co/" style="color:#0000FF;font-weight: bold; text-decoration: underline;">[Accurest.co]</a></p>
        </div>
        """

        return EmailService.send_email(subject, [user_email], body, html_body)
    
    @staticmethod
    def send_password_reset_success_email(user_email, user_name=None):
        subject = "Your Password Has Been Reset Successfully 🔐"

        body = f"""
        Hello {user_name or 'User'},

        We're confirming that your password was successfully reset. 
        If you didn’t request this change, please contact our support team immediately.

        Best regards,  
        The Accurest Team
        """

        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; color: #333;">
        <h2 style="color: #2c3e50;">Password Reset Confirmation</h2>
        <p>Hi {user_name or 'User'},</p>
        <p>We wanted to let you know that your password has been successfully changed.</p>
        <p>If this wasn’t you, please <strong>reset your password</strong> again immediately or contact support.</p>
        <p style="margin-top: 20px;">Stay secure!</p>
        <p>The Accurest Team</p>
        <p><a href="https://accurest.co/" style="color:#0000FF;font-weight: bold; text-decoration: underline;">[Accurest.co]</a></p>
        </div>
        """

        return EmailService.send_email(subject, [user_email], body, html_body)


    @staticmethod
    def send_account_created_email(user_email, user_name, role, temp_password, login_url):
        subject = f"Your {role} Account Has Been Created – Action Required"

        body = f"""
        Hello {user_name},

        Your {role} account has been successfully created. 🎉

        Please use the credentials below to log in:
        Email: {user_email}
        Temporary Password: {temp_password}

        Login Link: {login_url}

        You will be prompted to change your password upon first login.

        If you didn’t request this account, please contact our support team.

        Regards,  
        The Accurest Team
        """

        html_body = f"""
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 20px; color: #333;">
            <h2 style="color: #2c3e50;">Welcome to Accurest!</h2>
            <p>Hello <strong>{user_name}</strong>,</p>
            <p>Your <strong>{role}</strong> account has been created successfully.</p>
            <p><strong>Email:</strong> {user_email}</p>
            <p><strong>Temporary Password:</strong> {temp_password}</p>
            <p>Click below to log in and change your password:</p>
            <p style="margin: 0 3px;">
                <a href="{login_url}" style="background-color: #4CAF50; color: white; padding: 10px 20px;
                text-decoration: none; border-radius: 5px;">Login to Your Account</a>
            </p>
            <p>For your security, please change your password immediately after logging in.</p>
            <p style="margin-top: 20px;">Stay secure,<br>The Accurest Team</p>
            <p><a href="https://accurest.co/" style="color:#0000FF;font-weight: bold;">[Accurest.co]</a></p>
        </div>
        """

        return EmailService.send_email(subject, [user_email], body, html_body)