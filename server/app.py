#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe

class Signup(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        image_url = data.get('image_url')
        bio = data.get('bio')

        try:
            user = User(
                username=username,
                image_url=image_url,
                bio=bio,
            )
            # set password using setter which hashes
            if password is None:
                # Ensure we fail validation if no password provided
                raise ValueError('Password required')
            user.password_hash = password

            db.session.add(user)
            db.session.commit()

            session['user_id'] = user.id

            return user.to_dict(only=('id', 'username', 'image_url', 'bio')), 201
        except (IntegrityError, ValueError) as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

class CheckSession(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        user = User.query.get(user_id)
        if not user:
            return {'error': 'Unauthorized'}, 401
        return user.to_dict(only=('id', 'username', 'image_url', 'bio')), 200

class Login(Resource):
    def post(self):
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')

        user = User.query.filter_by(username=username).first()
        if user and user.authenticate(password):
            session['user_id'] = user.id
            return user.to_dict(only=('id', 'username', 'image_url', 'bio')), 200
        return {'error': 'Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401
        session['user_id'] = None
        return '', 204

class RecipeIndex(Resource):
    def get(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        # Return all recipes (lab text suggests viewing after login). Limit fields to avoid recursion.
        recipes = Recipe.query.all()
        return [r.to_dict(only=('id','title','instructions','minutes_to_complete')) for r in recipes], 200

    def post(self):
        user_id = session.get('user_id')
        if not user_id:
            return {'error': 'Unauthorized'}, 401

        data = request.get_json() or {}
        try:
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=user_id,
            )
            db.session.add(recipe)
            db.session.commit()
            return recipe.to_dict(only=('id','title','instructions','minutes_to_complete')), 201
        except (IntegrityError, ValueError) as e:
            db.session.rollback()
            return {'errors': [str(e)]}, 422

api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)