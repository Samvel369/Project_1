import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://samlion:Sam369333693@db:5432/social_network"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SECRET_KEY = os.getenv("SECRET_KEY", "fallback-secret-key")
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")