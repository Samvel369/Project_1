FROM python:3.10-slim-buster

WORKDIR /app

# Установим зависимости
RUN apt-get update && apt-get install -y build-essential && \
    pip install --upgrade pip && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install python-dotenv

COPY . .

# Создадим нужные папки
RUN mkdir -p /app/instance /app/static/uploads

EXPOSE 5000

CMD ["gunicorn", "--config", "gunicorn.conf.py", "wsgi:app"]
