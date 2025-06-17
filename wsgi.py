from app import app

# Эта строка нужна только при локальном запуске
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
