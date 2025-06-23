import os
from dotenv import load_dotenv

# Загружаем переменные окружения из файла .env (если он есть)
load_dotenv()

# Получаем строку подключения из переменной окружения или используем значение по умолчанию
SQLALCHEMY_DATABASE_URI = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@postgres_db:5432/postgres"
)

SQLALCHEMY_TRACK_MODIFICATIONS = False

# Секретный ключ для сессий и безопасности (можно заменить на свой)
SECRET_KEY = os.getenv("SECRET_KEY", "devkey")