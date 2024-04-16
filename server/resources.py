from flask.views import MethodView
from flask import request, jsonify, session
from app import db, bcrypt
from models import User

class Signup(MethodView):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        session['user_id'] = new_user.id

        return jsonify({'message': 'User created successfully', 'user': new_user.username})

class Login(MethodView):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            return jsonify({'message': 'Login successful', 'user': user.username})
        else:
            return jsonify({'message': 'Invalid username or password'}), 401

class Logout(MethodView):
    def delete(self):
        session.pop('user_id', None)
        return jsonify({'message': 'Logout successful'})

class CheckSession(MethodView):
    def get(self):
        if 'user_id' in session:
            user_id = session['user_id']
            user = User.query.get(user_id)
            return jsonify({'user': user.username})
        else:
            return '', 204
