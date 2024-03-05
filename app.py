import datetime
import hashlib
import json
import os
import logging
import re

import psycopg2
from dotenv import load_dotenv
import jwt
from flask import Flask, request, jsonify, Response
from db import DatabaseController, Base, create_engine
from auth import token_required

load_dotenv()
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URL'] = "postgresql:" + os.getenv("POSTGRES_CONN")[9:]
app.config['engine'] = create_engine(app.config['SQLALCHEMY_DATABASE_URL'])
Base.metadata.create_all(app.config['engine'])
app.config['SECRET_KEY'] = os.getenv('RANDOM_SECRET')
controller = DatabaseController(app.config['SQLALCHEMY_DATABASE_URL'])


@app.route('/api/ping', methods=['GET'])
def send():
    return jsonify({"status": "ok"}), 200


@app.route('/api/countries', methods=['GET'])
def countries():
    countries = controller.get_countries([i[1] for i in request.args.to_dict().items() if i[0] == "region"])
    print(request.args)
    return Response(json.dumps([dict(i) for i in countries]), 200, mimetype='application/json')


@app.route('/api/countries/<alpha2>', methods=["GET"])
def get_county_by_alpha2(alpha2):
    country = controller.get_countries_by_code(alpha2)
    if country:
        return jsonify(dict(country[0])), 200
    return jsonify({"reason": "Server can't find this countrie"}), 400


@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data:
        return jsonify({'reason': 'No data provided'}), 409

    login = data.get('login')
    email = data.get('email')
    password = data.get('password')
    country_code = data.get('countryCode')
    is_public = data.get('isPublic')
    phone = data.get('phone')
    image = data.get('image')

    if login is None or email is None or password is None or country_code is None or is_public is None:
        return jsonify({'reason': 'All fields are required'}), 409

    if not isinstance(is_public, bool):
        return jsonify({"reason": "Invalid is_public field"}), 400

    if not bool(re.match(r'^\+\d+$', phone)) or len(phone) > 20:
        return jsonify({'reason': 'Invalid phone number'}), 400

    if len(controller.get_countries_by_code(country_code)) < 1:
        return jsonify({'reason': 'Invalid country code'}), 409

    if image and len(image) > 200:
        return jsonify({'reason': 'Image url is too long'}), 409

    if not controller.user_uniqueness_check(login=login, phone=phone, email=email):
        return jsonify({'reason': 'User with this login, email or phone already exists'}), 400

    if not controller.check_password_reliability(password):
        return jsonify({'reason': 'Password is not secure'}), 400

    password_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    data["password"] = password_hash
    new_user = controller.create_user(data)
    filtered_user_dict = {k: v for k, v in new_user['profile'].items() if v is not None}
    return jsonify({'profile': filtered_user_dict}), 201


@app.route('/api/auth/sign-in', methods=['POST'])
def sign_in():
    user_data = request.get_json()
    username = user_data.get('login')
    password = user_data.get('password')
    if username is None or password is None:
        return jsonify({'reason': 'All fields are required'}), 409
    if not controller.get_user_by_password(username, password):
        return jsonify({'reason': 'User with this login and password not exists'}), 401

    exp = datetime.datetime.now(datetime.UTC) + datetime.timedelta(hours=1)
    token = jwt.encode(
        {
            'login': username,
            'exp': exp,
            'password': hashlib.sha256(password.encode('utf-8')).hexdigest()
        },
        app.config['SECRET_KEY'],
        algorithm='HS256'
    )
    return jsonify({'token': token}), 200


@app.route('/api/me/profile', methods=['GET'])
@token_required
def get_profile(login: str):
    return jsonify(controller.get_user_by_login(login)), 200


@app.route('/api/me/profile', methods=['PATCH'])
@token_required
def handle_patch(login: str):
    data = request.json
    country_code = data.get('countryCode')
    image = data.get('image')
    phone = data.get('phone')
    is_public = data.get('isPublic')
    if country_code is None or image is None or phone is None or is_public is None:
        return jsonify({'reason': 'All fields are required'}), 409

    if not controller.get_countries_by_code(country_code):
        return jsonify({"reason": "Invalid country code"}), 400

    if image and len(image) > 200:
        return jsonify({"reason": "Image too long"}), 400

    if not controller.user_uniqueness_check(login=login, phone=phone, user_login=login):
        return jsonify({'reason': 'User with this login, email or phone already exists'}), 409

    updated_user = controller.update_user(login=login, phone=phone, is_public=is_public, country_code=country_code,
                                          image=image)
    return jsonify(dict(updated_user)), 200


@app.route('/api/profiles/<plogin>', methods=['GET'])
@token_required
def get_profile_by_login(login: str, plogin: str):
    user_profile = controller.get_user_by_login(plogin)
    if not user_profile:
        return jsonify({"reason": "User does not exist."}), 403
    if user_profile.get('isPublic') is True:
        return jsonify(user_profile), 200
    elif login in [i.get("login") for i in controller.get_friends(limit=int(1e9), login=plogin, offset=0)]:
        return jsonify(user_profile), 200
    return jsonify({"reason": "the user has a private profile."}), 403


@app.route('/api/me/updatePassword', methods=['POST'])
@token_required
def update_password(login: str):
    data = request.get_json()
    old_password = data.get('oldPassword')
    new_password = data.get('newPassword')
    if new_password is None or old_password is None:
        return jsonify({"reason": "All fields are required."}), 400

    if not controller.check_password_reliability(new_password):
        return jsonify({'reason': 'Password is not secure'}), 400

    res = controller.update_password(old_password, new_password, login)
    if not res:
        return jsonify({"reason": "Password is incorrect"}), 403
    return jsonify({"status": "ok"}), 200


@app.route('/api/friends/add', methods=['POST'])
@token_required
def add_friend(login: str):
    friend_login = request.get_json().get('login')

    if friend_login is None:
        return jsonify({"reason": "All files are required."}), 400

    if login == friend_login:
        # print("login: {login} friend_login: {friend_login}".format(login=login, friend_login=friend_login))
        return jsonify({"status": "ok"}), 200

    if not controller.get_user_by_login(friend_login):
        return jsonify({"reason": "User does not exist."}), 404

    res = controller.add_friend(friend_login, login)
    return jsonify({"status": "ok"}), 200


@app.route('/api/friends/remove', methods=['POST'])
@token_required
def remove_friend(login: str):
    friend_login = request.get_json().get('login')
    controller.remove_friend(friend_login, login)
    return jsonify({"status": "ok"}), 200


@app.route('/api/friends', methods=['GET'])
@token_required
def get_my_friends(login: str):
    limit = request.args.get('limit', default=5)
    offset = request.args.get('offset', default=0)
    return jsonify(controller.get_friends(login, limit, offset))


@app.route('/api/posts/new', methods=['POST'])
@token_required
def create_new_post(login: str):
    post_data = request.get_json()
    content = post_data.get('content')
    tags = post_data.get('tags')
    return jsonify(controller.create_post(content, tags, login)), 201


@app.route('/api/posts/<int:post_id>', methods=['GET'])
@token_required
def get_post(login: str, post_id: int):
    post = controller.get_post_by_id(post_id)
    if not post:
        return jsonify({"reason": "No such post."}), 404
    return jsonify(post), 200


if __name__ == "__main__":
    app.run(host='localhost', port=8080, debug=True)
