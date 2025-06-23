import os
from dotenv import load_dotenv

# Загружаем переменные окружения из .env
load_dotenv()

class Config:
    # База данных: сначала из переменной окружения, иначе — дефолтная строка
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "DATABASE_URL",
        "postgresql://postgres:password@postgres_db:5432/postgres"
    )

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Секретный ключ
    SECRET_KEY = os.getenv("SECRET_KEY", "devkey")

    # Режим отладки
    DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")