from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import os
from models import db, User
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "devkey")
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:password@postgres_db:5432/postgres"
)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)
CORS(app)

@app.before_first_request
def create_tables():
    with app.app_context():
        db.create_all()

@app.context_processor
def inject_counts():
    online_threshold = datetime.utcnow() - timedelta(minutes=5)
    online_users_count = User.query.filter(User.last_online >= online_threshold).count()
    return dict(online_users_count=online_users_count)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        flash("Регистрация прошла успешно. Теперь войдите.")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session["user_id"] = user.id
            user.last_online = datetime.utcnow()
            db.session.commit()
            return redirect(url_for("index"))
        flash("Неверные имя пользователя или пароль")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("user_id", None)
    flash("Вы вышли из системы.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
