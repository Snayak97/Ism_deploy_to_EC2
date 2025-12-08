import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv(override=True)

class Config:
    SECRET_KEY = os.getenv('SECRET_KEY', 'supersecretkey')
    FRONTEND_URL= os.getenv("FRONTEND_URL")

    # db
    SQLALCHEMY_DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///fail.db')
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # jwt
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY")
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

    JWT_ACCESS_TOKEN_EXPIRES = timedelta(
        minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
    )
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(
        days=int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 1))
    )
    JWT_RESET_EXPIRY = timedelta(
        minutes=int(os.getenv("JWT_RESET_EXPIRY", 15))
    )

    # redis
    REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
    REDIS_PORT = int(os.getenv("REDIS_PORT", 6379))
    REDIS_DB = int(os.getenv("REDIS_DB", 0))
    JWT_ID_EXPIRY = int(os.getenv("JWT_ID_EXPIRY", 3600))  # seconds
    

    # mail
    MAIL_SERVER = 'smtp.gmail.com'
    MAIL_PORT = 587
    MAIL_USE_TLS = True
    MAIL_USE_SSL = False
    MAIL_USERNAME = os.getenv('EMAIL_HOST_USER')
    MAIL_PASSWORD = os.getenv('EMAIL_HOST_PASSWORD')
    # MAIL_DEFAULT_SENDER = EMAIL_HOST_USER  # Or get from env if you prefer

    EMAIL_VERIFICATION_SALT = os.getenv('EMAIL_VERIFICATION_SALT', 'email-verification')