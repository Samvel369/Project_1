import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret")
    JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "fallback-jwt")
    
    SQLALCHEMY_DATABASE_URI = os.getenv("DATABASE_URL", "sqlite:///instance/site.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")
    
    UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'uploads')

    RESET_INTERVAL = 86400  # 24 часа
    COOLDOWN_INTERVAL = 60  # 60 секунд