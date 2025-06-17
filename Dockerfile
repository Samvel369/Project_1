FROM python:3.10-slim-buster

WORKDIR /app

# Установим системные зависимости и обновим pip
RUN apt-get update && apt-get install -y build-essential && \
    pip install --upgrade pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Копируем зависимости и установим их
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install python-dotenv

# Копируем всё приложение
COPY . .

# Создаём папки, если их нет
RUN mkdir -p /app/instance /app/static/uploads

# Открываем порт
EXPOSE 5000

# Запускаем через gunicorn
CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:app"]
