import os
from dotenv import load_dotenv
load_dotenv()
from config import Config
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta
import os
import re
import time
from threading import Thread
from sqlalchemy import func, event
from sqlalchemy.orm import Session
from collections import defaultdict
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)
app.config.from_object(Config)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'fallback-secret')
app.config['DEBUG'] = os.getenv('DEBUG', 'False') == 'True'
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///site.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['RESET_INTERVAL'] = 60  # 60 seconds
app.config['COOLDOWN_INTERVAL'] = 600  # 10 minutes in seconds
app.config['CUSTOM_ACTION_LIFETIME'] = 600  # 10 minutes in seconds
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'fallback-jwt-key')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
jwt = JWTManager(app)
CORS(app)  # Разрешить кросс-доменные запросы

# Модель для связи пользователей и стандартных действий
class UserDailyAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    daily_action_id = db.Column(db.Integer, db.ForeignKey('daily_action.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Модель для связи пользователей и созданных действий
class UserCustomAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    custom_action_id = db.Column(db.Integer, db.ForeignKey('custom_action.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, declined
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    avatar = db.Column(db.String(20), nullable=False, default='default.jpg')
    birth_date = db.Column(db.Date)
    status = db.Column(db.String(100), default='Новый пользователь')
    last_online = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    actions = db.relationship('UserAction', backref='author', lazy=True)
    daily_actions = db.relationship('UserDailyAction', backref='user', lazy=True)
    custom_actions = db.relationship('UserCustomAction', backref='user', lazy=True)

    # Друзья
    sent_requests = db.relationship('Friendship',
                                    foreign_keys='Friendship.user_id',
                                    backref='sender',
                                    lazy=True)

    received_requests = db.relationship('Friendship',
                                       foreign_keys='Friendship.friend_id',
                                       backref='receiver',
                                       lazy=True)

    def get_friends(self):
        # Принятые запросы дружбы
        friends = []
        accepted_requests = Friendship.query.filter(
            ((Friendship.user_id == self.id) | (Friendship.friend_id == self.id)) &
            (Friendship.status == 'accepted')
        ).all()

        for fr in accepted_requests:
            if fr.user_id == self.id:
                friends.append(User.query.get(fr.friend_id))
            else:
                friends.append(User.query.get(fr.user_id))
        return friends

    def get_pending_requests(self):
        return Friendship.query.filter(
            Friendship.friend_id == self.id,
            Friendship.status == 'pending'
        ).all()

    def get_recommended_friends(self):
        # Пользователи, которые отмечали мои созданные действия
        recommended = []
        my_actions = CustomAction.query.filter_by(user_id=self.id).all()
        for action in my_actions:
            marks = UserCustomAction.query.filter_by(custom_action_id=action.id).all()
            for mark in marks:
                user = User.query.get(mark.user_id)
                if (user and user != self and 
                    not self.is_friend(user) and 
                    user not in recommended):
                    recommended.append(user)
        return recommended

    def is_friend(self, user):
        # Проверяем, являются ли пользователи друзьями
        friendship = Friendship.query.filter(
            ((Friendship.user_id == self.id) & (Friendship.friend_id == user.id)) |
            ((Friendship.user_id == user.id) & (Friendship.friend_id == self.id)),
            Friendship.status == 'accepted'
        ).first()
        return friendship is not None

class DailyAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(100), nullable=False)
    reset_time = db.Column(db.DateTime, default=datetime.utcnow)
    marks = db.relationship('UserDailyAction', backref='action', lazy=True)
    
    @property
    def count(self):
        # Рассчитываем количество активных отметок за последнюю минуту
        threshold = datetime.utcnow() - timedelta(seconds=app.config['RESET_INTERVAL'])
        return UserDailyAction.query.filter(
            UserDailyAction.daily_action_id == self.id,
            UserDailyAction.timestamp >= threshold
        ).count()

class CustomAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    reset_time = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship('User', backref=db.backref('created_actions', lazy=True))
    marks = db.relationship('UserCustomAction', backref='action', lazy=True)
    
    @property
    def count(self):
        # Рассчитываем количество активных отметок за все время жизни действия
        return UserCustomAction.query.filter(
            UserCustomAction.custom_action_id == self.id
        ).count()

class UserAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def reset_action_counts():
    """Функция для обновления времени сброса"""
    while True:
        time.sleep(app.config['RESET_INTERVAL'])
        now = datetime.utcnow()
        
        with app.app_context():
            # Обновляем время сброса для стандартных действий
            for action in DailyAction.query.all():
                action.reset_time = now
                db.session.add(action)
            
            # Обновляем время сброса для пользовательских действий
            for action in CustomAction.query.all():
                action.reset_time = now
                db.session.add(action)
            
            db.session.commit()
            print(f"Время сброса обновлено: {now}")

def cleanup_custom_actions():
    """Функция для удаления старых созданных действий"""
    while True:
        time.sleep(60)  # Проверка каждую минуту
        with app.app_context():
            threshold = datetime.utcnow() - timedelta(seconds=app.config['CUSTOM_ACTION_LIFETIME'])
            # Удаляем действия, созданные более 10 минут назад
            old_actions = CustomAction.query.filter(CustomAction.date_posted < threshold).all()
            for action in old_actions:
                # Сначала удаляем отметки
                UserCustomAction.query.filter_by(custom_action_id=action.id).delete()
                db.session.delete(action)
            db.session.commit()
            if old_actions:
                print(f"Удалено {len(old_actions)} старых созданных действий")

# Сериализаторы для API
def user_to_dict(user):
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'avatar': user.avatar,
        'status': user.status,
        'birth_date': user.birth_date.isoformat() if user.birth_date else None,
        'last_online': user.last_online.isoformat() if user.last_online else None,
        'is_admin': user.is_admin
    }

def daily_action_to_dict(action):
    return {
        'id': action.id,
        'content': action.content,
        'count': action.count
    }

def custom_action_to_dict(action):
    return {
        'id': action.id,
        'content': action.content,
        'user_id': action.user_id,
        'author_username': action.author.username,
        'date_posted': action.date_posted.isoformat(),
        'count': action.count
    }

def friendship_to_dict(friendship):
    return {
        'id': friendship.id,
        'user_id': friendship.user_id,
        'friend_id': friendship.friend_id,
        'status': friendship.status,
        'timestamp': friendship.timestamp.isoformat()
    }

# API Endpoints
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not username or not email or not password or not confirm_password:
        return jsonify({'error': 'Все поля обязательны для заполнения'}), 400

    if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[a-zA-Z]", password):
        return jsonify({'error': 'Пароль должен содержать минимум 8 символов, включая цифры и буквы'}), 400

    if password != confirm_password:
        return jsonify({'error': 'Пароли не совпадают'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Это имя пользователя уже занято'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Этот email уже используется'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=user.id)
    return jsonify({
        'message': 'Регистрация прошла успешно!',
        'access_token': access_token,
        'user': user_to_dict(user)
    }), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'access_token': access_token,
            'user': user_to_dict(user)
        }), 200
    else:
        return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def api_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    return jsonify(user_to_dict(user))

@app.route('/api/profile/update', methods=['PUT'])
@jwt_required()
def api_update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json()

    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    if 'status' in data:
        user.status = data['status']

    if 'birth_date' in data:
        try:
            birth_date = datetime.strptime(data['birth_date'], '%Y-%m-%d').date()
            user.birth_date = birth_date
        except ValueError:
            return jsonify({'error': 'Некорректная дата рождения'}), 400

    db.session.commit()
    return jsonify({'message': 'Профиль обновлен', 'user': user_to_dict(user)})

@app.route('/api/actions/standard', methods=['GET'])
def api_standard_actions():
    actions = DailyAction.query.all()
    return jsonify([daily_action_to_dict(a) for a in actions])

@app.route('/api/actions/custom', methods=['GET'])
def api_custom_actions():
    actions = CustomAction.query.order_by(CustomAction.date_posted.desc()).all()
    return jsonify([custom_action_to_dict(a) for a in actions])

@app.route('/api/actions/mark/daily/<int:action_id>', methods=['POST'])
@jwt_required()
def api_mark_daily_action(action_id):
    user_id = get_jwt_identity()
    action = DailyAction.query.get_or_404(action_id)

    # Проверка кулдауна
    last_mark = UserDailyAction.query.filter_by(
        user_id=user_id,
        daily_action_id=action_id
    ).order_by(UserDailyAction.timestamp.desc()).first()

    if last_mark and (datetime.utcnow() - last_mark.timestamp).seconds < app.config['COOLDOWN_INTERVAL']:
        return jsonify({
            'error': f'Вы уже отмечались недавно. Подождите {app.config["COOLDOWN_INTERVAL"]} секунд'
        }), 429

    # Создание отметки
    new_mark = UserDailyAction(user_id=user_id, daily_action_id=action_id)
    db.session.add(new_mark)
    db.session.commit()

    return jsonify({
        'success': True,
        'count': action.count
    })

@app.route('/api/actions/mark/custom/<int:action_id>', methods=['POST'])
@jwt_required()
def api_mark_custom_action(action_id):
    user_id = get_jwt_identity()
    action = CustomAction.query.get_or_404(action_id)

    # Проверка кулдауна
    last_mark = UserCustomAction.query.filter_by(
        user_id=user_id,
        custom_action_id=action_id
    ).order_by(UserCustomAction.timestamp.desc()).first()

    if last_mark and (datetime.utcnow() - last_mark.timestamp).seconds < app.config['COOLDOWN_INTERVAL']:
        return jsonify({
            'error': f'Вы уже отмечались недавно. Подождите {app.config["COOLDOWN_INTERVAL"]} секунд'
        }), 429

    # Создание отметки
    new_mark = UserCustomAction(user_id=user_id, custom_action_id=action_id)
    db.session.add(new_mark)
    db.session.commit()

    return jsonify({
        'success': True,
        'count': action.count
    })

@app.route('/api/actions/create', methods=['POST'])
@jwt_required()
def api_create_action():
    user_id = get_jwt_identity()
    data = request.get_json()
    content = data.get('content')

    if not content or len(content.strip()) < 3:
        return jsonify({'error': 'Содержание действия слишком короткое'}), 400

    action = CustomAction(content=content.strip(), user_id=user_id)
    db.session.add(action)
    db.session.commit()

    return jsonify(custom_action_to_dict(action)), 201

@app.route('/api/actions/personal', methods=['POST'])
@jwt_required()
def api_create_personal_action():
    user_id = get_jwt_identity()
    data = request.get_json()
    content = data.get('content')

    if not content or len(content.strip()) < 3:
        return jsonify({'error': 'Содержание действия слишком короткое'}), 400

    action = UserAction(content=content.strip(), user_id=user_id)
    db.session.add(action)
    db.session.commit()

    return jsonify({
        'id': action.id,
        'content': action.content,
        'date_posted': action.date_posted.isoformat()
    }), 201

@app.route('/api/actions/personal/<int:action_id>', methods=['DELETE'])
@jwt_required()
def api_delete_personal_action(action_id):
    user_id = get_jwt_identity()
    action = UserAction.query.get_or_404(action_id)

    if action.user_id != user_id:
        return jsonify({'error': 'Нет прав для удаления этого действия'}), 403

    db.session.delete(action)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/actions/publish/<int:action_id>', methods=['POST'])
@jwt_required()
def api_publish_action(action_id):
    user_id = get_jwt_identity()
    personal_action = UserAction.query.get_or_404(action_id)

    if personal_action.user_id != user_id:
        return jsonify({'error': 'Нет прав для публикации этого действия'}), 403

    custom_action = CustomAction(
        content=personal_action.content,
        user_id=user_id
    )
    db.session.add(custom_action)
    db.session.delete(personal_action)
    db.session.commit()

    return jsonify(custom_action_to_dict(custom_action)), 201

@app.route('/api/friends', methods=['GET'])
@jwt_required()
def api_friends():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    friends = [user_to_dict(f) for f in user.get_friends()]
    pending_requests = [friendship_to_dict(r) for r in user.get_pending_requests()]
    recommended = [user_to_dict(r) for r in user.get_recommended_friends()]

    return jsonify({
        'friends': friends,
        'pending_requests': pending_requests,
        'recommended': recommended
    })

@app.route('/api/friends/add/<int:friend_id>', methods=['POST'])
@jwt_required()
def api_add_friend(friend_id):
    user_id = get_jwt_identity()

    if user_id == friend_id:
        return jsonify({'error': 'Нельзя добавить себя в друзья'}), 400

    # Проверка существующего запроса
    existing_request = Friendship.query.filter(
        (Friendship.user_id == user_id) &
        (Friendship.friend_id == friend_id)
    ).first()

    if existing_request:
        return jsonify({'error': 'Запрос на добавление в друзья уже отправлен'}), 400

    new_request = Friendship(
        user_id=user_id,
        friend_id=friend_id,
        status='pending'
    )
    db.session.add(new_request)
    db.session.commit()

    return jsonify({'success': True}), 201

@app.route('/api/friends/accept/<int:request_id>', methods=['POST'])
@jwt_required()
def api_accept_friend(request_id):
    user_id = get_jwt_identity()
    friend_request = Friendship.query.get_or_404(request_id)

    if friend_request.friend_id != user_id:
        return jsonify({'error': 'Неверный запрос'}), 403

    friend_request.status = 'accepted'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friends/decline/<int:request_id>', methods=['POST'])
@jwt_required()
def api_decline_friend(request_id):
    user_id = get_jwt_identity()
    friend_request = Friendship.query.get_or_404(request_id)

    if friend_request.friend_id != user_id:
        return jsonify({'error': 'Неверный запрос'}), 403

    db.session.delete(friend_request)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friends/remove/<int:friend_id>', methods=['POST'])
@jwt_required()
def api_remove_friend(friend_id):
    user_id = get_jwt_identity()
    friendship = Friendship.query.filter(
        ((Friendship.user_id == user_id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == user_id))
    ).first()

    if not friendship:
        return jsonify({'error': 'Пользователь не найден в друзьях'}), 404

    db.session.delete(friendship)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/user/<int:user_id>', methods=['GET'])
@jwt_required()
def api_get_user(user_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    is_friend = User.query.get(current_user_id).is_friend(user)
    user_data = user_to_dict(user)
    user_data['is_friend'] = is_friend

    return jsonify(user_data)

@app.route('/api/stats/daily/<int:action_id>', methods=['GET'])
@jwt_required()
def api_daily_action_stats(action_id):
    action = DailyAction.query.get_or_404(action_id)

    # Получаем отметки за последние 10 минут
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)

    marks = UserDailyAction.query.filter(
        UserDailyAction.daily_action_id == action_id,
        UserDailyAction.timestamp >= ten_minutes_ago
    ).order_by(UserDailyAction.timestamp).all()

    stats = defaultdict(list)
    for mark in marks:
        minute_key = mark.timestamp.replace(second=0, microsecond=0)
        stats[minute_key].append(mark.user.username)

    minute_stats = []
    for minute, users in sorted(stats.items(), key=lambda x: x[0], reverse=True):
        minute_stats.append({
            'time': minute.strftime('%H:%M'),
            'count': len(users),
            'users': users
        })

    return jsonify({
        'action': daily_action_to_dict(action),
        'minute_stats': minute_stats,
        'recent_marks': [mark.user.username for mark in marks[:20]]
    })

@app.route('/api/stats/custom/<int:action_id>', methods=['GET'])
@jwt_required()
def api_custom_action_stats(action_id):
    action = CustomAction.query.get_or_404(action_id)

    # Получаем отметки за последние 10 минут
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)

    marks = UserCustomAction.query.filter(
        UserCustomAction.custom_action_id == action_id,
        UserCustomAction.timestamp >= ten_minutes_ago
    ).order_by(UserCustomAction.timestamp).all()

    stats = defaultdict(list)
    for mark in marks:
        minute_key = mark.timestamp.replace(second=0, microsecond=0)
        stats[minute_key].append(mark.user.username)

    minute_stats = []
    for minute, users in sorted(stats.items(), key=lambda x: x[0], reverse=True):
        minute_stats.append({
            'time': minute.strftime('%H:%M'),
            'count': len(users),
            'users': users
        })

    return jsonify({
        'action': custom_action_to_dict(action),
        'minute_stats': minute_stats,
        'recent_marks': [mark.user.username for mark in marks[:20]]
    })

# Веб-интерфейс
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[a-zA-Z]", password):
            flash('Пароль должен содержать минимум 8 символов, включая цифры и буквы', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Пароли не совпадают', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Это имя пользователя уже занято', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Этот email уже используется', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'status' in request.form:
            current_user.status = request.form['status']
        
        if 'birth_date' in request.form:
            try:
                birth_date = datetime.strptime(request.form['birth_date'], '%Y-%m-%d').date()
                current_user.birth_date = birth_date
            except ValueError:
                flash('Некорректная дата рождения', 'danger')
        
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"user_{current_user.id}.{file.filename.rsplit('.', 1)[1].lower()}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.avatar = filename
        
        if 'action_content' in request.form and request.form['action_content'].strip():
            action = UserAction(content=request.form['action_content'], author=current_user)
            db.session.add(action)
        
        db.session.commit()
        flash('Профиль обновлен!', 'success')
        return redirect(url_for('profile'))
    
    user_actions = UserAction.query.filter_by(user_id=current_user.id).order_by(UserAction.date_posted.desc()).all()
    
    # История отметок
    daily_marks = UserDailyAction.query.filter_by(user_id=current_user.id).order_by(UserDailyAction.timestamp.desc()).all()
    custom_marks = UserCustomAction.query.filter_by(user_id=current_user.id).order_by(UserCustomAction.timestamp.desc()).all()
    
    # Созданные действия
    created_actions = CustomAction.query.filter_by(user_id=current_user.id).order_by(CustomAction.date_posted.desc()).all()
    
    return render_template('profile.html', 
                         actions=user_actions,
                         daily_marks=daily_marks,
                         custom_marks=custom_marks,
                         created_actions=created_actions)

@app.route('/user/<int:user_id>')
@login_required
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Проверяем, является ли пользователь другом
    is_friend = current_user.is_friend(user)
    
    # Если не друг и не администратор, показываем ограниченный профиль
    if not is_friend and not current_user.is_admin and user != current_user:
        return render_template('limited_profile.html', user=user)
    
    # Полный профиль для друзей, самого себя или администратора
    user_actions = UserAction.query.filter_by(user_id=user_id).order_by(UserAction.date_posted.desc()).all()
    created_actions = CustomAction.query.filter_by(user_id=user_id).order_by(CustomAction.date_posted.desc()).all()
    
    return render_template('full_profile.html', 
                         user=user,
                         actions=user_actions,
                         created_actions=created_actions,
                         is_friend=is_friend)

@app.route('/add_friend/<int:friend_id>', methods=['POST'])
@login_required
def add_friend(friend_id):
    if friend_id == current_user.id:
        flash('Нельзя добавить себя в друзья', 'danger')
        return redirect(url_for('profile'))
    
    # Проверяем, не отправлен ли уже запрос
    existing_request = Friendship.query.filter(
        (Friendship.user_id == current_user.id) & 
        (Friendship.friend_id == friend_id)
    ).first()
    
    if existing_request:
        flash('Запрос на добавление в друзья уже отправлен', 'info')
    else:
        new_request = Friendship(
            user_id=current_user.id,
            friend_id=friend_id,
            status='pending'
        )
        db.session.add(new_request)
        db.session.commit()
        flash('Запрос на добавление в друзья отправлен!', 'success')
    
    return redirect(url_for('view_user', user_id=friend_id))

@app.route('/accept_friend/<int:request_id>', methods=['POST'])
@login_required
def accept_friend(request_id):
    friend_request = Friendship.query.get_or_404(request_id)
    
    if friend_request.friend_id != current_user.id:
        flash('Неверный запрос', 'danger')
        return redirect(url_for('profile'))
    
    friend_request.status = 'accepted'
    db.session.commit()
    flash('Пользователь добавлен в друзья!', 'success')
    return redirect(url_for('profile'))

@app.route('/decline_friend/<int:request_id>', methods=['POST'])
@login_required
def decline_friend(request_id):
    friend_request = Friendship.query.get_or_404(request_id)
    
    if friend_request.friend_id != current_user.id:
        flash('Неверный запрос', 'danger')
        return redirect(url_for('profile'))
    
    db.session.delete(friend_request)
    db.session.commit()
    flash('Запрос в друзья отклонен', 'success')
    return redirect(url_for('profile'))

@app.route('/remove_friend/<int:friend_id>', methods=['POST'])
@login_required
def remove_friend(friend_id):
    friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == current_user.id))
    ).first()
    
    if friendship:
        db.session.delete(friendship)
        db.session.commit()
        flash('Пользователь удален из друзей', 'success')
    else:
        flash('Пользователь не найден в друзьях', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    # Удаляем все отметки пользователя
    UserDailyAction.query.filter_by(user_id=current_user.id).delete()
    UserCustomAction.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('История отметок очищена!', 'success')
    return redirect(url_for('profile'))

@app.route('/clear_created_actions', methods=['POST'])
@login_required
def clear_created_actions():
    # Удаляем все созданные пользователем действия
    CustomAction.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('История созданных действий очищена!', 'success')
    return redirect(url_for('profile'))

@app.route('/delete_mark/<mark_type>/<int:mark_id>', methods=['POST'])
@login_required
def delete_mark(mark_type, mark_id):
    if mark_type == 'daily':
        mark = UserDailyAction.query.get_or_404(mark_id)
    elif mark_type == 'custom':
        mark = UserCustomAction.query.get_or_404(mark_id)
    else:
        flash('Неверный тип отметки', 'danger')
        return redirect(url_for('profile'))
    
    if mark.user_id == current_user.id or current_user.is_admin:
        db.session.delete(mark)
        db.session.commit()
        flash('Отметка удалена!', 'success')
    else:
        flash('Нет прав для удаления этой отметки', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/delete_created_action/<int:action_id>', methods=['POST'])
@login_required
def delete_created_action(action_id):
    action = CustomAction.query.get_or_404(action_id)
    if action.user_id == current_user.id or current_user.is_admin:
        # Удаляем все отметки этого действия
        UserCustomAction.query.filter_by(custom_action_id=action.id).delete()
        db.session.delete(action)
        db.session.commit()
        flash('Созданное действие удалено!', 'success')
    else:
        flash('Нет прав для удаления этого действия', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/add_standard_action', methods=['POST'])
@login_required
def add_standard_action():
    if not current_user.is_admin:
        flash('Только администратор может добавлять стандартные действия', 'danger')
        return redirect(url_for('our_world'))
    
    new_action = request.form.get('new_action')
    if new_action and len(new_action.strip()) > 0:
        action = DailyAction(content=new_action.strip())
        db.session.add(action)
        db.session.commit()
        flash('Стандартное действие добавлено!', 'success')
    else:
        flash('Нельзя добавить пустое действие', 'danger')
    
    return redirect(url_for('our_world'))

@app.route('/delete_standard_action/<int:action_id>', methods=['POST'])
@login_required
def delete_standard_action(action_id):
    if not current_user.is_admin:
        flash('Только администратор может удалять стандартные действия', 'danger')
        return redirect(url_for('our_world'))
    
    action = DailyAction.query.get_or_404(action_id)
    # Удаляем все отметки этого действия
    UserDailyAction.query.filter_by(daily_action_id=action.id).delete()
    db.session.delete(action)
    db.session.commit()
    flash('Стандартное действие удалено!', 'success')
    return redirect(url_for('our_world'))

@app.route('/add_personal_action', methods=['POST'])
@login_required
def add_personal_action():
    action_content = request.form.get('action_content')
    if action_content and len(action_content.strip()) > 0:
        action = UserAction(content=action_content.strip(), author=current_user)
        db.session.add(action)
        db.session.commit()
        flash('Личное действие добавлено!', 'success')
    else:
        flash('Нельзя добавить пустое действие', 'danger')
    
    return redirect(url_for('our_world'))

@app.route('/delete_personal_action/<int:action_id>', methods=['POST'])
@login_required
def delete_personal_action(action_id):
    action = UserAction.query.get_or_404(action_id)
    if action.user_id != current_user.id and not current_user.is_admin:
        flash('Нет прав для удаления этого действия', 'danger')
        return redirect(url_for('our_world'))
    
    db.session.delete(action)
    db.session.commit()
    flash('Личное действие удалено!', 'success')
    return redirect(url_for('our_world'))

@app.route('/publish_action/<int:action_id>', methods=['POST'])
@login_required
def publish_action(action_id):
    personal_action = UserAction.query.get_or_404(action_id)
    if personal_action.user_id != current_user.id and not current_user.is_admin:
        flash('Нет прав для публикации этого действия', 'danger')
        return redirect(url_for('our_world'))
    
    # Создаем новое действие в CustomAction
    custom_action = CustomAction(
        content=personal_action.content,
        user_id=current_user.id
    )
    db.session.add(custom_action)
    # Удаляем личное действие
    db.session.delete(personal_action)
    db.session.commit()
    flash('Действие опубликовано!', 'success')
    return redirect(url_for('our_world'))

@app.route('/delete_custom_action/<int:action_id>', methods=['POST'])
@login_required
def delete_custom_action(action_id):
    action = CustomAction.query.get_or_404(action_id)
    if action.user_id != current_user.id and not current_user.is_admin:
        flash('Нет прав для удаления этого действия', 'danger')
        return redirect(url_for('our_world'))
    
    # Удаляем все отметки этого действия
    UserCustomAction.query.filter_by(custom_action_id=action.id).delete()
    db.session.delete(action)
    db.session.commit()
    flash('Созданное действие удалено!', 'success')
    return redirect(url_for('our_world'))

@app.route('/mark_daily_action/<int:action_id>', methods=['POST'])
@login_required
def mark_daily_action(action_id):
    action = DailyAction.query.get_or_404(action_id)
    
    # Проверяем, не отметился ли пользователь уже недавно
    last_mark = UserDailyAction.query.filter_by(
        user_id=current_user.id,
        daily_action_id=action_id
    ).order_by(UserDailyAction.timestamp.desc()).first()
    
    if last_mark and (datetime.utcnow() - last_mark.timestamp).seconds < app.config['COOLDOWN_INTERVAL']:
        return jsonify({
            'error': True,
            'message': f'Вы уже отмечались недавно. Подождите {app.config["COOLDOWN_INTERVAL"]} секунд'
        })
    
    # Создаем новую отметку
    new_mark = UserDailyAction(
        user_id=current_user.id,
        daily_action_id=action_id
    )
    db.session.add(new_mark)
    db.session.commit()
    
    # Возвращаем обновленное количество отметок
    return jsonify({
        'success': True,
        'count': action.count
    })

@app.route('/mark_custom_action/<int:action_id>', methods=['POST'])
@login_required
def mark_custom_action(action_id):
    action = CustomAction.query.get_or_404(action_id)
    
    # Проверяем, не отметился ли пользователь уже недавно
    last_mark = UserCustomAction.query.filter_by(
        user_id=current_user.id,
        custom_action_id=action_id
    ).order_by(UserCustomAction.timestamp.desc()).first()
    
    if last_mark and (datetime.utcnow() - last_mark.timestamp).seconds < app.config['COOLDOWN_INTERVAL']:
        return jsonify({
            'error': True,
            'message': f'Вы уже отмечались недавно. Подождите {app.config["COOLDOWN_INTERVAL"]} секунд'
        })
    
    # Создаем новую отметку
    new_mark = UserCustomAction(
        user_id=current_user.id,
        custom_action_id=action_id
    )
    db.session.add(new_mark)
    db.session.commit()
    
    # Возвращаем обновленное количество отметок
    return jsonify({
        'success': True,
        'count': action.count
    })

@app.route('/get_action_counts')
def get_action_counts():
    # Получаем количество отметок для всех стандартных действий
    standard_actions = {}
    for action in DailyAction.query.all():
        standard_actions[action.id] = action.count
    
    # Получаем количество отметок для всех пользовательских действий
    custom_actions = {}
    for action in CustomAction.query.all():
        custom_actions[action.id] = action.count
    
    return jsonify({
        'standard_actions': standard_actions,
        'custom_actions': custom_actions
    })

@app.route('/our_world')
@login_required
def our_world():
    current_user.last_online = datetime.utcnow()
    db.session.commit()
    
    # Стандартные действия (10 штук)
    standard_actions = DailyAction.query.order_by(DailyAction.id).all()
    if not standard_actions:
        # Инициализация стандартных действий при первом запуске
        standard_contents = [
            "Играю на гитаре", "Смотрю футбол", "Делаю зарядку",
            "Чихнул", "Смеюсь", "Отдыхаю", "Работаю",
            "Играю в компьютер", "Гуляю", "Стою в пробке"
        ]
        for content in standard_contents:
            action = DailyAction(content=content)
            db.session.add(action)
        db.session.commit()
        standard_actions = DailyAction.query.order_by(DailyAction.id).all()
    
    # Созданные пользователями действия
    custom_actions = CustomAction.query.order_by(CustomAction.date_posted.desc()).all()
    
    # Личные действия пользователя
    my_actions = UserAction.query.filter_by(user_id=current_user.id)\
                      .order_by(UserAction.date_posted.desc()).all()
    
    # Передаем RESET_INTERVAL в шаблон
    reset_interval = app.config['RESET_INTERVAL']
    
    return render_template('our_world.html', 
                         standard_actions=standard_actions,
                         custom_actions=custom_actions,
                         my_actions=my_actions,
                         reset_interval=reset_interval)

@app.route('/daily_action/<int:action_id>')
@login_required
def daily_action_stats(action_id):
    action = DailyAction.query.get_or_404(action_id)
    
    # Получаем отметки за последние 10 минут
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)
    
    # Группируем отметки по минутам
    marks = UserDailyAction.query.filter(
        UserDailyAction.daily_action_id == action_id,
        UserDailyAction.timestamp >= ten_minutes_ago
    ).order_by(UserDailyAction.timestamp).all()
    
    # Создаем структуру для хранения статистики по минутам
    stats = defaultdict(list)
    for mark in marks:
        minute_key = mark.timestamp.replace(second=0, microsecond=0)
        stats[minute_key].append(mark)
    
    # Форматируем статистику для отображения
    minute_stats = []
    for minute, marks in sorted(stats.items(), key=lambda x: x[0], reverse=True):
        minute_stats.append({
            'time': minute.strftime('%H:%M'),
            'count': len(marks),
            'users': [mark.user.username for mark in marks]
        })
    
    # Последние отметки (для списка пользователей)
    recent_marks = marks[:20]  # Ограничиваем количество
    
    return render_template('action_stats.html', 
                         action=action,
                         action_type='daily',
                         minute_stats=minute_stats,
                         recent_marks=recent_marks)

@app.route('/custom_action/<int:action_id>')
@login_required
def custom_action_stats(action_id):
    action = CustomAction.query.get_or_404(action_id)
    
    # Получаем отметки за последние 10 минут
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)
    
    # Группируем отметки по минутам
    marks = UserCustomAction.query.filter(
        UserCustomAction.custom_action_id == action_id,
        UserCustomAction.timestamp >= ten_minutes_ago
    ).order_by(UserCustomAction.timestamp).all()
    
    # Создаем структуру для хранения статистики по минутам
    stats = defaultdict(list)
    for mark in marks:
        minute_key = mark.timestamp.replace(second=0, microsecond=0)
        stats[minute_key].append(mark)
    
    # Форматируем статистику для отображения
    minute_stats = []
    for minute, marks in sorted(stats.items(), key=lambda x: x[0], reverse=True):
        minute_stats.append({
            'time': minute.strftime('%H:%M'),
            'count': len(marks),
            'users': [mark.user.username for mark in marks]
        })
    
    # Последние отметки (для списка пользователей)
    recent_marks = marks[:20]  # Ограничиваем количество
    
    return render_template('action_stats.html', 
                         action=action,
                         action_type='custom',
                         minute_stats=minute_stats,
                         recent_marks=recent_marks)

# Контекстный процессор для добавления счетчиков пользователей во все шаблоны
@app.context_processor
def inject_counts():
    online_threshold = datetime.utcnow() - timedelta(minutes=5)
    online_users_count = User.query.filter(User.last_online >= online_threshold).count()
    total_users_count = User.query.count()
    return {
        'online_users_count': online_users_count,
        'total_users_count': total_users_count
    }

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        db.create_all()
        # Создаем администратора
        admin_username = "SamLion"
        if not User.query.filter_by(username=admin_username).first():
            hashed_pw = bcrypt.generate_password_hash('369333693').decode('utf-8')
            admin = User(username=admin_username, email='admin@example.com', 
                        password=hashed_pw, is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print(f"Создан администратор: {admin_username}")
        
        # Запускаем поток для обновления времени сброса
        reset_thread = Thread(target=reset_action_counts, daemon=True)
        reset_thread.start()

        # Запускаем поток для очистки старых созданных действий
        cleanup_thread = Thread(target=cleanup_custom_actions, daemon=True)
        cleanup_thread.start()
    
    app.run(host="0.0.0.0", port=5000)
from config import Config
from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_bcrypt import Bcrypt
from werkzeug.utils import secure_filename
from datetime import datetime, date, timedelta
import os
import re
import time
from threading import Thread
from sqlalchemy import func, event
from sqlalchemy.orm import Session
from collections import defaultdict
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS

app = Flask(__name__)
app.config.from_object(Config)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['RESET_INTERVAL'] = 60  # 60 seconds
app.config['COOLDOWN_INTERVAL'] = 600  # 10 minutes in seconds
app.config['CUSTOM_ACTION_LIFETIME'] = 600  # 10 minutes in seconds
app.config['JWT_SECRET_KEY'] = 'your-jwt-secret-key'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=1)

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
jwt = JWTManager(app)
CORS(app)  # Разрешить кросс-доменные запросы

# Модель для связи пользователей и стандартных действий
class UserDailyAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    daily_action_id = db.Column(db.Integer, db.ForeignKey('daily_action.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Модель для связи пользователей и созданных действий
class UserCustomAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    custom_action_id = db.Column(db.Integer, db.ForeignKey('custom_action.id'))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Friendship(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, declined
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    avatar = db.Column(db.String(20), nullable=False, default='default.jpg')
    birth_date = db.Column(db.Date)
    status = db.Column(db.String(100), default='Новый пользователь')
    last_online = db.Column(db.DateTime, default=datetime.utcnow)
    is_admin = db.Column(db.Boolean, default=False)
    actions = db.relationship('UserAction', backref='author', lazy=True)
    daily_actions = db.relationship('UserDailyAction', backref='user', lazy=True)
    custom_actions = db.relationship('UserCustomAction', backref='user', lazy=True)

    # Друзья
    sent_requests = db.relationship('Friendship',
                                    foreign_keys='Friendship.user_id',
                                    backref='sender',
                                    lazy=True)

    received_requests = db.relationship('Friendship',
                                       foreign_keys='Friendship.friend_id',
                                       backref='receiver',
                                       lazy=True)

    def get_friends(self):
        # Принятые запросы дружбы
        friends = []
        accepted_requests = Friendship.query.filter(
            ((Friendship.user_id == self.id) | (Friendship.friend_id == self.id)) &
            (Friendship.status == 'accepted')
        ).all()

        for fr in accepted_requests:
            if fr.user_id == self.id:
                friends.append(User.query.get(fr.friend_id))
            else:
                friends.append(User.query.get(fr.user_id))
        return friends

    def get_pending_requests(self):
        return Friendship.query.filter(
            Friendship.friend_id == self.id,
            Friendship.status == 'pending'
        ).all()

    def get_recommended_friends(self):
        # Пользователи, которые отмечали мои созданные действия
        recommended = []
        my_actions = CustomAction.query.filter_by(user_id=self.id).all()
        for action in my_actions:
            marks = UserCustomAction.query.filter_by(custom_action_id=action.id).all()
            for mark in marks:
                user = User.query.get(mark.user_id)
                if (user and user != self and 
                    not self.is_friend(user) and 
                    user not in recommended):
                    recommended.append(user)
        return recommended

    def is_friend(self, user):
        # Проверяем, являются ли пользователи друзьями
        friendship = Friendship.query.filter(
            ((Friendship.user_id == self.id) & (Friendship.friend_id == user.id)) |
            ((Friendship.user_id == user.id) & (Friendship.friend_id == self.id)),
            Friendship.status == 'accepted'
        ).first()
        return friendship is not None

class DailyAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(100), nullable=False)
    reset_time = db.Column(db.DateTime, default=datetime.utcnow)
    marks = db.relationship('UserDailyAction', backref='action', lazy=True)
    
    @property
    def count(self):
        # Рассчитываем количество активных отметок за последнюю минуту
        threshold = datetime.utcnow() - timedelta(seconds=app.config['RESET_INTERVAL'])
        return UserDailyAction.query.filter(
            UserDailyAction.daily_action_id == self.id,
            UserDailyAction.timestamp >= threshold
        ).count()

class CustomAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    reset_time = db.Column(db.DateTime, default=datetime.utcnow)
    author = db.relationship('User', backref=db.backref('created_actions', lazy=True))
    marks = db.relationship('UserCustomAction', backref='action', lazy=True)
    
    @property
    def count(self):
        # Рассчитываем количество активных отметок за все время жизни действия
        return UserCustomAction.query.filter(
            UserCustomAction.custom_action_id == self.id
        ).count()

class UserAction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(300), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def reset_action_counts():
    """Функция для обновления времени сброса"""
    while True:
        time.sleep(app.config['RESET_INTERVAL'])
        now = datetime.utcnow()
        
        with app.app_context():
            # Обновляем время сброса для стандартных действий
            for action in DailyAction.query.all():
                action.reset_time = now
                db.session.add(action)
            
            # Обновляем время сброса для пользовательских действий
            for action in CustomAction.query.all():
                action.reset_time = now
                db.session.add(action)
            
            db.session.commit()
            print(f"Время сброса обновлено: {now}")

def cleanup_custom_actions():
    """Функция для удаления старых созданных действий"""
    while True:
        time.sleep(60)  # Проверка каждую минуту
        with app.app_context():
            threshold = datetime.utcnow() - timedelta(seconds=app.config['CUSTOM_ACTION_LIFETIME'])
            # Удаляем действия, созданные более 10 минут назад
            old_actions = CustomAction.query.filter(CustomAction.date_posted < threshold).all()
            for action in old_actions:
                # Сначала удаляем отметки
                UserCustomAction.query.filter_by(custom_action_id=action.id).delete()
                db.session.delete(action)
            db.session.commit()
            if old_actions:
                print(f"Удалено {len(old_actions)} старых созданных действий")

# Сериализаторы для API
def user_to_dict(user):
    return {
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'avatar': user.avatar,
        'status': user.status,
        'birth_date': user.birth_date.isoformat() if user.birth_date else None,
        'last_online': user.last_online.isoformat() if user.last_online else None,
        'is_admin': user.is_admin
    }

def daily_action_to_dict(action):
    return {
        'id': action.id,
        'content': action.content,
        'count': action.count
    }

def custom_action_to_dict(action):
    return {
        'id': action.id,
        'content': action.content,
        'user_id': action.user_id,
        'author_username': action.author.username,
        'date_posted': action.date_posted.isoformat(),
        'count': action.count
    }

def friendship_to_dict(friendship):
    return {
        'id': friendship.id,
        'user_id': friendship.user_id,
        'friend_id': friendship.friend_id,
        'status': friendship.status,
        'timestamp': friendship.timestamp.isoformat()
    }

# API Endpoints
@app.route('/api/register', methods=['POST'])
def api_register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    confirm_password = data.get('confirm_password')

    if not username or not email or not password or not confirm_password:
        return jsonify({'error': 'Все поля обязательны для заполнения'}), 400

    if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[a-zA-Z]", password):
        return jsonify({'error': 'Пароль должен содержать минимум 8 символов, включая цифры и буквы'}), 400

    if password != confirm_password:
        return jsonify({'error': 'Пароли не совпадают'}), 400

    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Это имя пользователя уже занято'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Этот email уже используется'}), 400

    hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
    user = User(username=username, email=email, password=hashed_password)
    db.session.add(user)
    db.session.commit()

    access_token = create_access_token(identity=user.id)
    return jsonify({
        'message': 'Регистрация прошла успешно!',
        'access_token': access_token,
        'user': user_to_dict(user)
    }), 201

@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        access_token = create_access_token(identity=user.id)
        return jsonify({
            'access_token': access_token,
            'user': user_to_dict(user)
        }), 200
    else:
        return jsonify({'error': 'Неверное имя пользователя или пароль'}), 401

@app.route('/api/profile', methods=['GET'])
@jwt_required()
def api_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    return jsonify(user_to_dict(user))

@app.route('/api/profile/update', methods=['PUT'])
@jwt_required()
def api_update_profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    data = request.get_json()

    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    if 'status' in data:
        user.status = data['status']

    if 'birth_date' in data:
        try:
            birth_date = datetime.strptime(data['birth_date'], '%Y-%m-%d').date()
            user.birth_date = birth_date
        except ValueError:
            return jsonify({'error': 'Некорректная дата рождения'}), 400

    db.session.commit()
    return jsonify({'message': 'Профиль обновлен', 'user': user_to_dict(user)})

@app.route('/api/actions/standard', methods=['GET'])
def api_standard_actions():
    actions = DailyAction.query.all()
    return jsonify([daily_action_to_dict(a) for a in actions])

@app.route('/api/actions/custom', methods=['GET'])
def api_custom_actions():
    actions = CustomAction.query.order_by(CustomAction.date_posted.desc()).all()
    return jsonify([custom_action_to_dict(a) for a in actions])

@app.route('/api/actions/mark/daily/<int:action_id>', methods=['POST'])
@jwt_required()
def api_mark_daily_action(action_id):
    user_id = get_jwt_identity()
    action = DailyAction.query.get_or_404(action_id)

    # Проверка кулдауна
    last_mark = UserDailyAction.query.filter_by(
        user_id=user_id,
        daily_action_id=action_id
    ).order_by(UserDailyAction.timestamp.desc()).first()

    if last_mark and (datetime.utcnow() - last_mark.timestamp).seconds < app.config['COOLDOWN_INTERVAL']:
        return jsonify({
            'error': f'Вы уже отмечались недавно. Подождите {app.config["COOLDOWN_INTERVAL"]} секунд'
        }), 429

    # Создание отметки
    new_mark = UserDailyAction(user_id=user_id, daily_action_id=action_id)
    db.session.add(new_mark)
    db.session.commit()

    return jsonify({
        'success': True,
        'count': action.count
    })

@app.route('/api/actions/mark/custom/<int:action_id>', methods=['POST'])
@jwt_required()
def api_mark_custom_action(action_id):
    user_id = get_jwt_identity()
    action = CustomAction.query.get_or_404(action_id)

    # Проверка кулдауна
    last_mark = UserCustomAction.query.filter_by(
        user_id=user_id,
        custom_action_id=action_id
    ).order_by(UserCustomAction.timestamp.desc()).first()

    if last_mark and (datetime.utcnow() - last_mark.timestamp).seconds < app.config['COOLDOWN_INTERVAL']:
        return jsonify({
            'error': f'Вы уже отмечались недавно. Подождите {app.config["COOLDOWN_INTERVAL"]} секунд'
        }), 429

    # Создание отметки
    new_mark = UserCustomAction(user_id=user_id, custom_action_id=action_id)
    db.session.add(new_mark)
    db.session.commit()

    return jsonify({
        'success': True,
        'count': action.count
    })

@app.route('/api/actions/create', methods=['POST'])
@jwt_required()
def api_create_action():
    user_id = get_jwt_identity()
    data = request.get_json()
    content = data.get('content')

    if not content or len(content.strip()) < 3:
        return jsonify({'error': 'Содержание действия слишком короткое'}), 400

    action = CustomAction(content=content.strip(), user_id=user_id)
    db.session.add(action)
    db.session.commit()

    return jsonify(custom_action_to_dict(action)), 201

@app.route('/api/actions/personal', methods=['POST'])
@jwt_required()
def api_create_personal_action():
    user_id = get_jwt_identity()
    data = request.get_json()
    content = data.get('content')

    if not content or len(content.strip()) < 3:
        return jsonify({'error': 'Содержание действия слишком короткое'}), 400

    action = UserAction(content=content.strip(), user_id=user_id)
    db.session.add(action)
    db.session.commit()

    return jsonify({
        'id': action.id,
        'content': action.content,
        'date_posted': action.date_posted.isoformat()
    }), 201

@app.route('/api/actions/personal/<int:action_id>', methods=['DELETE'])
@jwt_required()
def api_delete_personal_action(action_id):
    user_id = get_jwt_identity()
    action = UserAction.query.get_or_404(action_id)

    if action.user_id != user_id:
        return jsonify({'error': 'Нет прав для удаления этого действия'}), 403

    db.session.delete(action)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/actions/publish/<int:action_id>', methods=['POST'])
@jwt_required()
def api_publish_action(action_id):
    user_id = get_jwt_identity()
    personal_action = UserAction.query.get_or_404(action_id)

    if personal_action.user_id != user_id:
        return jsonify({'error': 'Нет прав для публикации этого действия'}), 403

    custom_action = CustomAction(
        content=personal_action.content,
        user_id=user_id
    )
    db.session.add(custom_action)
    db.session.delete(personal_action)
    db.session.commit()

    return jsonify(custom_action_to_dict(custom_action)), 201

@app.route('/api/friends', methods=['GET'])
@jwt_required()
def api_friends():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)

    friends = [user_to_dict(f) for f in user.get_friends()]
    pending_requests = [friendship_to_dict(r) for r in user.get_pending_requests()]
    recommended = [user_to_dict(r) for r in user.get_recommended_friends()]

    return jsonify({
        'friends': friends,
        'pending_requests': pending_requests,
        'recommended': recommended
    })

@app.route('/api/friends/add/<int:friend_id>', methods=['POST'])
@jwt_required()
def api_add_friend(friend_id):
    user_id = get_jwt_identity()

    if user_id == friend_id:
        return jsonify({'error': 'Нельзя добавить себя в друзья'}), 400

    # Проверка существующего запроса
    existing_request = Friendship.query.filter(
        (Friendship.user_id == user_id) &
        (Friendship.friend_id == friend_id)
    ).first()

    if existing_request:
        return jsonify({'error': 'Запрос на добавление в друзья уже отправлен'}), 400

    new_request = Friendship(
        user_id=user_id,
        friend_id=friend_id,
        status='pending'
    )
    db.session.add(new_request)
    db.session.commit()

    return jsonify({'success': True}), 201

@app.route('/api/friends/accept/<int:request_id>', methods=['POST'])
@jwt_required()
def api_accept_friend(request_id):
    user_id = get_jwt_identity()
    friend_request = Friendship.query.get_or_404(request_id)

    if friend_request.friend_id != user_id:
        return jsonify({'error': 'Неверный запрос'}), 403

    friend_request.status = 'accepted'
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friends/decline/<int:request_id>', methods=['POST'])
@jwt_required()
def api_decline_friend(request_id):
    user_id = get_jwt_identity()
    friend_request = Friendship.query.get_or_404(request_id)

    if friend_request.friend_id != user_id:
        return jsonify({'error': 'Неверный запрос'}), 403

    db.session.delete(friend_request)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/friends/remove/<int:friend_id>', methods=['POST'])
@jwt_required()
def api_remove_friend(friend_id):
    user_id = get_jwt_identity()
    friendship = Friendship.query.filter(
        ((Friendship.user_id == user_id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == user_id))
    ).first()

    if not friendship:
        return jsonify({'error': 'Пользователь не найден в друзьях'}), 404

    db.session.delete(friendship)
    db.session.commit()
    return jsonify({'success': True})

@app.route('/api/user/<int:user_id>', methods=['GET'])
@jwt_required()
def api_get_user(user_id):
    current_user_id = get_jwt_identity()
    user = User.query.get(user_id)

    if not user:
        return jsonify({'error': 'Пользователь не найден'}), 404

    is_friend = User.query.get(current_user_id).is_friend(user)
    user_data = user_to_dict(user)
    user_data['is_friend'] = is_friend

    return jsonify(user_data)

@app.route('/api/stats/daily/<int:action_id>', methods=['GET'])
@jwt_required()
def api_daily_action_stats(action_id):
    action = DailyAction.query.get_or_404(action_id)

    # Получаем отметки за последние 10 минут
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)

    marks = UserDailyAction.query.filter(
        UserDailyAction.daily_action_id == action_id,
        UserDailyAction.timestamp >= ten_minutes_ago
    ).order_by(UserDailyAction.timestamp).all()

    stats = defaultdict(list)
    for mark in marks:
        minute_key = mark.timestamp.replace(second=0, microsecond=0)
        stats[minute_key].append(mark.user.username)

    minute_stats = []
    for minute, users in sorted(stats.items(), key=lambda x: x[0], reverse=True):
        minute_stats.append({
            'time': minute.strftime('%H:%M'),
            'count': len(users),
            'users': users
        })

    return jsonify({
        'action': daily_action_to_dict(action),
        'minute_stats': minute_stats,
        'recent_marks': [mark.user.username for mark in marks[:20]]
    })

@app.route('/api/stats/custom/<int:action_id>', methods=['GET'])
@jwt_required()
def api_custom_action_stats(action_id):
    action = CustomAction.query.get_or_404(action_id)

    # Получаем отметки за последние 10 минут
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)

    marks = UserCustomAction.query.filter(
        UserCustomAction.custom_action_id == action_id,
        UserCustomAction.timestamp >= ten_minutes_ago
    ).order_by(UserCustomAction.timestamp).all()

    stats = defaultdict(list)
    for mark in marks:
        minute_key = mark.timestamp.replace(second=0, microsecond=0)
        stats[minute_key].append(mark.user.username)

    minute_stats = []
    for minute, users in sorted(stats.items(), key=lambda x: x[0], reverse=True):
        minute_stats.append({
            'time': minute.strftime('%H:%M'),
            'count': len(users),
            'users': users
        })

    return jsonify({
        'action': custom_action_to_dict(action),
        'minute_stats': minute_stats,
        'recent_marks': [mark.user.username for mark in marks[:20]]
    })

# Веб-интерфейс
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if len(password) < 8 or not re.search(r"\d", password) or not re.search(r"[a-zA-Z]", password):
            flash('Пароль должен содержать минимум 8 символов, включая цифры и буквы', 'danger')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Пароли не совпадают', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(username=username).first():
            flash('Это имя пользователя уже занято', 'danger')
            return redirect(url_for('register'))

        if User.query.filter_by(email=email).first():
            flash('Этот email уже используется', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = User(username=username, email=email, password=hashed_password)
        db.session.add(user)
        db.session.commit()

        flash('Регистрация прошла успешно! Теперь вы можете войти', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('profile'))
        else:
            flash('Неверное имя пользователя или пароль', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Вы вышли из системы', 'info')
    return redirect(url_for('index'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        if 'status' in request.form:
            current_user.status = request.form['status']
        
        if 'birth_date' in request.form:
            try:
                birth_date = datetime.strptime(request.form['birth_date'], '%Y-%m-%d').date()
                current_user.birth_date = birth_date
            except ValueError:
                flash('Некорректная дата рождения', 'danger')
        
        if 'avatar' in request.files:
            file = request.files['avatar']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"user_{current_user.id}.{file.filename.rsplit('.', 1)[1].lower()}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.avatar = filename
        
        if 'action_content' in request.form and request.form['action_content'].strip():
            action = UserAction(content=request.form['action_content'], author=current_user)
            db.session.add(action)
        
        db.session.commit()
        flash('Профиль обновлен!', 'success')
        return redirect(url_for('profile'))
    
    user_actions = UserAction.query.filter_by(user_id=current_user.id).order_by(UserAction.date_posted.desc()).all()
    
    # История отметок
    daily_marks = UserDailyAction.query.filter_by(user_id=current_user.id).order_by(UserDailyAction.timestamp.desc()).all()
    custom_marks = UserCustomAction.query.filter_by(user_id=current_user.id).order_by(UserCustomAction.timestamp.desc()).all()
    
    # Созданные действия
    created_actions = CustomAction.query.filter_by(user_id=current_user.id).order_by(CustomAction.date_posted.desc()).all()
    
    return render_template('profile.html', 
                         actions=user_actions,
                         daily_marks=daily_marks,
                         custom_marks=custom_marks,
                         created_actions=created_actions)

@app.route('/user/<int:user_id>')
@login_required
def view_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Проверяем, является ли пользователь другом
    is_friend = current_user.is_friend(user)
    
    # Если не друг и не администратор, показываем ограниченный профиль
    if not is_friend and not current_user.is_admin and user != current_user:
        return render_template('limited_profile.html', user=user)
    
    # Полный профиль для друзей, самого себя или администратора
    user_actions = UserAction.query.filter_by(user_id=user_id).order_by(UserAction.date_posted.desc()).all()
    created_actions = CustomAction.query.filter_by(user_id=user_id).order_by(CustomAction.date_posted.desc()).all()
    
    return render_template('full_profile.html', 
                         user=user,
                         actions=user_actions,
                         created_actions=created_actions,
                         is_friend=is_friend)

@app.route('/add_friend/<int:friend_id>', methods=['POST'])
@login_required
def add_friend(friend_id):
    if friend_id == current_user.id:
        flash('Нельзя добавить себя в друзья', 'danger')
        return redirect(url_for('profile'))
    
    # Проверяем, не отправлен ли уже запрос
    existing_request = Friendship.query.filter(
        (Friendship.user_id == current_user.id) & 
        (Friendship.friend_id == friend_id)
    ).first()
    
    if existing_request:
        flash('Запрос на добавление в друзья уже отправлен', 'info')
    else:
        new_request = Friendship(
            user_id=current_user.id,
            friend_id=friend_id,
            status='pending'
        )
        db.session.add(new_request)
        db.session.commit()
        flash('Запрос на добавление в друзья отправлен!', 'success')
    
    return redirect(url_for('view_user', user_id=friend_id))

@app.route('/accept_friend/<int:request_id>', methods=['POST'])
@login_required
def accept_friend(request_id):
    friend_request = Friendship.query.get_or_404(request_id)
    
    if friend_request.friend_id != current_user.id:
        flash('Неверный запрос', 'danger')
        return redirect(url_for('profile'))
    
    friend_request.status = 'accepted'
    db.session.commit()
    flash('Пользователь добавлен в друзья!', 'success')
    return redirect(url_for('profile'))

@app.route('/decline_friend/<int:request_id>', methods=['POST'])
@login_required
def decline_friend(request_id):
    friend_request = Friendship.query.get_or_404(request_id)
    
    if friend_request.friend_id != current_user.id:
        flash('Неверный запрос', 'danger')
        return redirect(url_for('profile'))
    
    db.session.delete(friend_request)
    db.session.commit()
    flash('Запрос в друзья отклонен', 'success')
    return redirect(url_for('profile'))

@app.route('/remove_friend/<int:friend_id>', methods=['POST'])
@login_required
def remove_friend(friend_id):
    friendship = Friendship.query.filter(
        ((Friendship.user_id == current_user.id) & (Friendship.friend_id == friend_id)) |
        ((Friendship.user_id == friend_id) & (Friendship.friend_id == current_user.id))
    ).first()
    
    if friendship:
        db.session.delete(friendship)
        db.session.commit()
        flash('Пользователь удален из друзей', 'success')
    else:
        flash('Пользователь не найден в друзьях', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/clear_history', methods=['POST'])
@login_required
def clear_history():
    # Удаляем все отметки пользователя
    UserDailyAction.query.filter_by(user_id=current_user.id).delete()
    UserCustomAction.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('История отметок очищена!', 'success')
    return redirect(url_for('profile'))

@app.route('/clear_created_actions', methods=['POST'])
@login_required
def clear_created_actions():
    # Удаляем все созданные пользователем действия
    CustomAction.query.filter_by(user_id=current_user.id).delete()
    db.session.commit()
    flash('История созданных действий очищена!', 'success')
    return redirect(url_for('profile'))

@app.route('/delete_mark/<mark_type>/<int:mark_id>', methods=['POST'])
@login_required
def delete_mark(mark_type, mark_id):
    if mark_type == 'daily':
        mark = UserDailyAction.query.get_or_404(mark_id)
    elif mark_type == 'custom':
        mark = UserCustomAction.query.get_or_404(mark_id)
    else:
        flash('Неверный тип отметки', 'danger')
        return redirect(url_for('profile'))
    
    if mark.user_id == current_user.id or current_user.is_admin:
        db.session.delete(mark)
        db.session.commit()
        flash('Отметка удалена!', 'success')
    else:
        flash('Нет прав для удаления этой отметки', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/delete_created_action/<int:action_id>', methods=['POST'])
@login_required
def delete_created_action(action_id):
    action = CustomAction.query.get_or_404(action_id)
    if action.user_id == current_user.id or current_user.is_admin:
        # Удаляем все отметки этого действия
        UserCustomAction.query.filter_by(custom_action_id=action.id).delete()
        db.session.delete(action)
        db.session.commit()
        flash('Созданное действие удалено!', 'success')
    else:
        flash('Нет прав для удаления этого действия', 'danger')
    
    return redirect(url_for('profile'))

@app.route('/add_standard_action', methods=['POST'])
@login_required
def add_standard_action():
    if not current_user.is_admin:
        flash('Только администратор может добавлять стандартные действия', 'danger')
        return redirect(url_for('our_world'))
    
    new_action = request.form.get('new_action')
    if new_action and len(new_action.strip()) > 0:
        action = DailyAction(content=new_action.strip())
        db.session.add(action)
        db.session.commit()
        flash('Стандартное действие добавлено!', 'success')
    else:
        flash('Нельзя добавить пустое действие', 'danger')
    
    return redirect(url_for('our_world'))

@app.route('/delete_standard_action/<int:action_id>', methods=['POST'])
@login_required
def delete_standard_action(action_id):
    if not current_user.is_admin:
        flash('Только администратор может удалять стандартные действия', 'danger')
        return redirect(url_for('our_world'))
    
    action = DailyAction.query.get_or_404(action_id)
    # Удаляем все отметки этого действия
    UserDailyAction.query.filter_by(daily_action_id=action.id).delete()
    db.session.delete(action)
    db.session.commit()
    flash('Стандартное действие удалено!', 'success')
    return redirect(url_for('our_world'))

@app.route('/add_personal_action', methods=['POST'])
@login_required
def add_personal_action():
    action_content = request.form.get('action_content')
    if action_content and len(action_content.strip()) > 0:
        action = UserAction(content=action_content.strip(), author=current_user)
        db.session.add(action)
        db.session.commit()
        flash('Личное действие добавлено!', 'success')
    else:
        flash('Нельзя добавить пустое действие', 'danger')
    
    return redirect(url_for('our_world'))

@app.route('/delete_personal_action/<int:action_id>', methods=['POST'])
@login_required
def delete_personal_action(action_id):
    action = UserAction.query.get_or_404(action_id)
    if action.user_id != current_user.id and not current_user.is_admin:
        flash('Нет прав для удаления этого действия', 'danger')
        return redirect(url_for('our_world'))
    
    db.session.delete(action)
    db.session.commit()
    flash('Личное действие удалено!', 'success')
    return redirect(url_for('our_world'))

@app.route('/publish_action/<int:action_id>', methods=['POST'])
@login_required
def publish_action(action_id):
    personal_action = UserAction.query.get_or_404(action_id)
    if personal_action.user_id != current_user.id and not current_user.is_admin:
        flash('Нет прав для публикации этого действия', 'danger')
        return redirect(url_for('our_world'))
    
    # Создаем новое действие в CustomAction
    custom_action = CustomAction(
        content=personal_action.content,
        user_id=current_user.id
    )
    db.session.add(custom_action)
    # Удаляем личное действие
    db.session.delete(personal_action)
    db.session.commit()
    flash('Действие опубликовано!', 'success')
    return redirect(url_for('our_world'))

@app.route('/delete_custom_action/<int:action_id>', methods=['POST'])
@login_required
def delete_custom_action(action_id):
    action = CustomAction.query.get_or_404(action_id)
    if action.user_id != current_user.id and not current_user.is_admin:
        flash('Нет прав для удаления этого действия', 'danger')
        return redirect(url_for('our_world'))
    
    # Удаляем все отметки этого действия
    UserCustomAction.query.filter_by(custom_action_id=action.id).delete()
    db.session.delete(action)
    db.session.commit()
    flash('Созданное действие удалено!', 'success')
    return redirect(url_for('our_world'))

@app.route('/mark_daily_action/<int:action_id>', methods=['POST'])
@login_required
def mark_daily_action(action_id):
    action = DailyAction.query.get_or_404(action_id)
    
    # Проверяем, не отметился ли пользователь уже недавно
    last_mark = UserDailyAction.query.filter_by(
        user_id=current_user.id,
        daily_action_id=action_id
    ).order_by(UserDailyAction.timestamp.desc()).first()
    
    if last_mark and (datetime.utcnow() - last_mark.timestamp).seconds < app.config['COOLDOWN_INTERVAL']:
        return jsonify({
            'error': True,
            'message': f'Вы уже отмечались недавно. Подождите {app.config["COOLDOWN_INTERVAL"]} секунд'
        })
    
    # Создаем новую отметку
    new_mark = UserDailyAction(
        user_id=current_user.id,
        daily_action_id=action_id
    )
    db.session.add(new_mark)
    db.session.commit()
    
    # Возвращаем обновленное количество отметок
    return jsonify({
        'success': True,
        'count': action.count
    })

@app.route('/mark_custom_action/<int:action_id>', methods=['POST'])
@login_required
def mark_custom_action(action_id):
    action = CustomAction.query.get_or_404(action_id)
    
    # Проверяем, не отметился ли пользователь уже недавно
    last_mark = UserCustomAction.query.filter_by(
        user_id=current_user.id,
        custom_action_id=action_id
    ).order_by(UserCustomAction.timestamp.desc()).first()
    
    if last_mark and (datetime.utcnow() - last_mark.timestamp).seconds < app.config['COOLDOWN_INTERVAL']:
        return jsonify({
            'error': True,
            'message': f'Вы уже отмечались недавно. Подождите {app.config["COOLDOWN_INTERVAL"]} секунд'
        })
    
    # Создаем новую отметку
    new_mark = UserCustomAction(
        user_id=current_user.id,
        custom_action_id=action_id
    )
    db.session.add(new_mark)
    db.session.commit()
    
    # Возвращаем обновленное количество отметок
    return jsonify({
        'success': True,
        'count': action.count
    })

@app.route('/get_action_counts')
def get_action_counts():
    # Получаем количество отметок для всех стандартных действий
    standard_actions = {}
    for action in DailyAction.query.all():
        standard_actions[action.id] = action.count
    
    # Получаем количество отметок для всех пользовательских действий
    custom_actions = {}
    for action in CustomAction.query.all():
        custom_actions[action.id] = action.count
    
    return jsonify({
        'standard_actions': standard_actions,
        'custom_actions': custom_actions
    })

@app.route('/our_world')
@login_required
def our_world():
    current_user.last_online = datetime.utcnow()
    db.session.commit()
    
    # Стандартные действия (10 штук)
    standard_actions = DailyAction.query.order_by(DailyAction.id).all()
    if not standard_actions:
        # Инициализация стандартных действий при первом запуске
        standard_contents = [
            "Играю на гитаре", "Смотрю футбол", "Делаю зарядку",
            "Чихнул", "Смеюсь", "Отдыхаю", "Работаю",
            "Играю в компьютер", "Гуляю", "Стою в пробке"
        ]
        for content in standard_contents:
            action = DailyAction(content=content)
            db.session.add(action)
        db.session.commit()
        standard_actions = DailyAction.query.order_by(DailyAction.id).all()
    
    # Созданные пользователями действия
    custom_actions = CustomAction.query.order_by(CustomAction.date_posted.desc()).all()
    
    # Личные действия пользователя
    my_actions = UserAction.query.filter_by(user_id=current_user.id)\
                      .order_by(UserAction.date_posted.desc()).all()
    
    # Передаем RESET_INTERVAL в шаблон
    reset_interval = app.config['RESET_INTERVAL']
    
    return render_template('our_world.html', 
                         standard_actions=standard_actions,
                         custom_actions=custom_actions,
                         my_actions=my_actions,
                         reset_interval=reset_interval)

@app.route('/daily_action/<int:action_id>')
@login_required
def daily_action_stats(action_id):
    action = DailyAction.query.get_or_404(action_id)
    
    # Получаем отметки за последние 10 минут
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)
    
    # Группируем отметки по минутам
    marks = UserDailyAction.query.filter(
        UserDailyAction.daily_action_id == action_id,
        UserDailyAction.timestamp >= ten_minutes_ago
    ).order_by(UserDailyAction.timestamp).all()
    
    # Создаем структуру для хранения статистики по минутам
    stats = defaultdict(list)
    for mark in marks:
        minute_key = mark.timestamp.replace(second=0, microsecond=0)
        stats[minute_key].append(mark)
    
    # Форматируем статистику для отображения
    minute_stats = []
    for minute, marks in sorted(stats.items(), key=lambda x: x[0], reverse=True):
        minute_stats.append({
            'time': minute.strftime('%H:%M'),
            'count': len(marks),
            'users': [mark.user.username for mark in marks]
        })
    
    # Последние отметки (для списка пользователей)
    recent_marks = marks[:20]  # Ограничиваем количество
    
    return render_template('action_stats.html', 
                         action=action,
                         action_type='daily',
                         minute_stats=minute_stats,
                         recent_marks=recent_marks)

@app.route('/custom_action/<int:action_id>')
@login_required
def custom_action_stats(action_id):
    action = CustomAction.query.get_or_404(action_id)
    
    # Получаем отметки за последние 10 минут
    now = datetime.utcnow()
    ten_minutes_ago = now - timedelta(minutes=10)
    
    # Группируем отметки по минутам
    marks = UserCustomAction.query.filter(
        UserCustomAction.custom_action_id == action_id,
        UserCustomAction.timestamp >= ten_minutes_ago
    ).order_by(UserCustomAction.timestamp).all()
    
    # Создаем структуру для хранения статистики по минутам
    stats = defaultdict(list)
    for mark in marks:
        minute_key = mark.timestamp.replace(second=0, microsecond=0)
        stats[minute_key].append(mark)
    
    # Форматируем статистику для отображения
    minute_stats = []
    for minute, marks in sorted(stats.items(), key=lambda x: x[0], reverse=True):
        minute_stats.append({
            'time': minute.strftime('%H:%M'),
            'count': len(marks),
            'users': [mark.user.username for mark in marks]
        })
    
    # Последние отметки (для списка пользователей)
    recent_marks = marks[:20]  # Ограничиваем количество
    
    return render_template('action_stats.html', 
                         action=action,
                         action_type='custom',
                         minute_stats=minute_stats,
                         recent_marks=recent_marks)

# Контекстный процессор для добавления счетчиков пользователей во все шаблоны
@app.context_processor
def inject_counts():
    online_threshold = datetime.utcnow() - timedelta(minutes=5)
    online_users_count = User.query.filter(User.last_online >= online_threshold).count()
    total_users_count = User.query.count()
    return {
        'online_users_count': online_users_count,
        'total_users_count': total_users_count
    }

if __name__ == '__main__':
    with app.app_context():
        if not os.path.exists(app.config['UPLOAD_FOLDER']):
            os.makedirs(app.config['UPLOAD_FOLDER'])
        db.create_all()
        # Создаем администратора
        admin_username = "SamLion"
        if not User.query.filter_by(username=admin_username).first():
            hashed_pw = bcrypt.generate_password_hash('369333693').decode('utf-8')
            admin = User(username=admin_username, email='admin@example.com', 
                        password=hashed_pw, is_admin=True)
            db.session.add(admin)
            db.session.commit()
            print(f"Создан администратор: {admin_username}")
        
        # Запускаем поток для обновления времени сброса
        reset_thread = Thread(target=reset_action_counts, daemon=True)
        reset_thread.start()

        # Запускаем поток для очистки старых созданных действий
        cleanup_thread = Thread(target=cleanup_custom_actions, daemon=True)
        cleanup_thread.start()
    
    app.run(host="0.0.0.0", port=5000)