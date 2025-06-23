from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from models import db, User
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'postgresql://samlion:Sam369333693@db:5432/social_network')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

@app.route("/")
def index():
    return "Сайт работает!"

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True, host="0.0.0.0")
