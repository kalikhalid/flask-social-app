import datetime
from functools import wraps
import jwt
from flask import jsonify, request
import os
from db import DatabaseController
from dotenv import load_dotenv
load_dotenv()

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            words = request.headers.get("Authorization").split(" ")
            token = words[1] if len(words) > 1 else None
        if not token:
            return jsonify({"reason": "Authentication Token is missing!"}), 401
        try:
            data = jwt.decode(token, os.getenv('RANDOM_SECRET'), algorithms=['HS256'])
            current_user = data['login']
            current_user_password_hash = data['password']
            controller = DatabaseController("postgresql:" + os.getenv("POSTGRES_CONN")[9:])
            if not controller.get_user_by_login(current_user):
                return jsonify({"reason": "Invalid login credentials"}), 403
            current_user_data = controller.get_user(current_user)
            if data['exp'] < datetime.datetime.now(datetime.UTC).timestamp():
                return jsonify({"reason": "Token is dead("}), 401
            if current_user_password_hash != current_user_data['password']:
                return jsonify({"reason": "Wrong password"}), 401
        except Exception as e:
            return jsonify({'reason': 'Token is invalid!'}), 401
        return f(current_user, *args, **kwargs)
    return decorated
