import bcrypt
from flask import Blueprint, jsonify, request, url_for
from flask_login import login_user, logout_user
from flask_mail import Message
import jwt
from datetime import datetime
from backend.models.user import Token
import secrets

from werkzeug.security import generate_password_hash
from services.email_generator import send_reset_email

from backend.core.extensions import db, mail
from backend.models.user import User, PasswordResetToken

auth_bp = Blueprint("auth", __name__)
SECRET_KEY = secrets.token_hex(32)  #Генерация ключа, мб поместить в другое место

@auth_bp.route("/login", methods=["POST"])
def login():
    data = request.json
    user = User.query.filter_by(email=data["email"]).first()
    if user and bcrypt.checkpw(data["password"].encode('utf-8'), user.user_passhash.encode('utf-8')):
        login_user(user)
        return jsonify({"message": "Login successful"}), 200
    return jsonify({"error": "Invalid credentials"}), 401

@auth_bp.route("/logout", methods=["POST"])
def logout():
    logout_user()
    return jsonify({"message": "Logout successful"}), 200

@auth_bp.route("/reset_password", methods=["POST"])
def reset_password():
    data = request.json
    user = User.query.filter_by(email=data["email"]).first()
    if not user:
        return jsonify({"error": "User not found"}), 404

    #создаем токен
    token = jwt.encode({
        "sub": user.id,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1) #время действия токена 1 час
    }, SECRET_KEY, algorithm="HS256")
    reset_url = url_for("auth.complete_reset", token=token, _external=True)

    msg = Message("Password Reset Request", recipients=[user.email])
    msg.body = f"To reset your password, visit the following link: {reset_url}"
    mail.send(msg)

    return jsonify({"message": "Reset link sent"}), 200

@auth_bp.route("/reset_password/<token>", methods=["POST"])
def complete_reset(token):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithm=["HS256"])
        user_id = payload["sub"]
    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Token has expired"}), 400
    except jwt.InvalidTokenError:
        return jsonify({"error": "Invalid token"}), 400
    user = User.query.get(user_id)
    if not user:
        return jsonify({"error": "Invalid token"}), 400

    data = request.json
    user.set_password(data["password"])
    db.session.commit()
    return jsonify({"message": "Password reset successful"}), 200

@auth_bp.route("/change_password", methods=["POST"])
def change_password():
    data = request.json
    token_str = data.get("token")
    new_password = data.get("new_password")

    if not token_str or not new_password:
        return jsonify({"error": "Missing token or new password"}), 400

    token = Token.query.filter_by(token=token_str).first()
    if not token:
        return jsonify({"error": "Invalid token"}), 400

    if token.expires_at < datetime.utcnow():
        db.session.delete(token)
        db.session.commit()
        return jsonify({"error": "Token has expired"}), 400

    user = User.query.get(token.user_id)
    if not user:
        return jsonify({"error": "User not found"}), 404

    user.set_password(new_password)
    db.session.delete(token)
    db.session.commit()

    return jsonify({"message": "Password changed successfully"}), 200




@auth_bp.route("/register", methods=["POST"])
def register():
    data = request.json

    if not all(key in data for key in ("first_name", "last_name", "phone_number", "email", "password")):
        return jsonify({"error": "Missing required fields"}), 400

    existing_user = User.query.filter_by(email=data["email"]).first()
    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    new_user = User(
        first_name=data["first_name"],
        last_name=data["last_name"],
        phone_number=data["phone_number"],
        email=data["email"],
        password_hash=generate_password_hash(data["password"]),
        role_id=2  # Обычный пользователь
    )
    db.session.add(new_user)
    db.session.commit()


    token = secrets.token_urlsafe(32)
    reset_token = PasswordResetToken(user_id=new_user.id, token=token)
    db.session.add(reset_token)
    db.session.commit()


    reset_url = f"https://website.ru/reset-password?token={token}"

    send_reset_email(new_user.email, reset_url)

    return jsonify({"message": "User registered. Check your email for password reset link."}), 201