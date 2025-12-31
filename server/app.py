#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource

from config import app, db, api
from models import User, UserSchema


class Signup(Resource):

    def post(self):
    
        json_data = request.get_json(force=True)
        new_user = User(
            username=json_data['username']
        )
        new_user.password_hash = json_data['password']
        db.session.add(new_user)
        db.session.commit()

        user_schema = UserSchema()
        user_data = user_schema.dump(new_user)

        session['user_id'] = new_user.id

        return user_data, 201

class CheckSession(Resource):

    def get(self):
        user_id = session.get('user_id')
        if user_id:
            user = User.query.filter(User.id == user_id).first()
            user_schema = UserSchema()
            return user_schema.dump(user), 200
        return {}, 204

class Login(Resource):

    def post(self):
        json_data = request.get_json(force=True)
        user = User.query.filter(User.username == json_data['username']).first()

        if user and user.authenticate(json_data['password']):
            session['user_id'] = user.id
            user_schema = UserSchema()
            return user_schema.dump(user), 200
        
        return {'error': 'Invalid username or password'}, 401

class Logout(Resource):

    def delete(self):
        session['user_id'] = None
        return {}, 204

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')

if __name__ == '__main__':
    app.run(port=5555, debug=True)

