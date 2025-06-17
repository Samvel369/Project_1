#!/bin/bash

# Обновление системы
sudo apt update && sudo apt upgrade -y

# Установка Docker
sudo apt install -y docker.io docker-compose
sudo systemctl enable --now docker

# Установка Nginx
sudo apt install -y nginx
sudo systemctl enable --now nginx

# Создание конфига Nginx
sudo bash -c 'cat > /etc/nginx/sites-available/social_network << EOF
server {
    listen 80;
    server_name your-domain.com; # Замените на ваш домен

    location / {
        proxy_pass http://localhost:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /static {
        alias /app/static;
        expires 30d;
    }
}
EOF'

# Активация конфига Nginx
sudo ln -s /etc/nginx/sites-available/social_network /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Клонирование репозитория
git clone https://github.com/your-username/your-repo.git
cd your-repo

# Создание .env файла
cp .env.example .env
# ЗАПОЛНИТЕ .env ФАЙЛ СВОИМИ ДАННЫМИ!

# Сборка и запуск Docker-контейнера
sudo docker-compose up -d --build

# Проверка работы
echo "Приложение запущено! Откройте http://your-domain.com"