from sqlalchemy.orm import validates
from sqlalchemy.ext.hybrid import hybrid_property
from sqlalchemy_serializer import SerializerMixin

from config import db, bcrypt

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, unique=True, nullable=False)
    _password_hash = db.Column(db.String, nullable=True)
    image_url = db.Column(db.String)
    bio = db.Column(db.String)

    # Relationships
    recipes = db.relationship('Recipe', backref='user', cascade='all, delete-orphan')

    # Serialization rules: never expose password hash
    serialize_rules = ('-_password_hash',)

    @hybrid_property
    def password_hash(self):
        # Prevent reading password hash
        raise AttributeError('password_hash is not a readable attribute')

    @password_hash.setter
    def password_hash(self, password):
        # Generate a bcrypt hash from the plain password
        if not password or not isinstance(password, str):
            raise ValueError('Password must be a non-empty string')
        self._password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

    def authenticate(self, password):
        if not self._password_hash:
            return False
        if password is None:
            return False
        return bcrypt.check_password_hash(self._password_hash, password)

    @validates('username')
    def validate_username(self, key, value):
        if not value or not isinstance(value, str) or not value.strip():
            raise ValueError('Username must be present')
        return value.strip()

class Recipe(db.Model, SerializerMixin):
    __tablename__ = 'recipes'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String, nullable=False)
    instructions = db.Column(db.String, nullable=False)
    minutes_to_complete = db.Column(db.Integer, nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)

    # Include nested user by default when serializing recipes, but exclude sensitive fields
    serialize_rules = ('-user._password_hash',)

    @validates('title')
    def validate_title(self, key, value):
        if not value or not isinstance(value, str) or not value.strip():
            raise ValueError('Title must be present')
        return value.strip()

    @validates('instructions')
    def validate_instructions(self, key, value):
        if not value or not isinstance(value, str) or len(value.strip()) < 50:
            raise ValueError('Instructions must be at least 50 characters long')
        return value

    @validates('minutes_to_complete')
    def validate_minutes(self, key, value):
        if value is None:
            raise ValueError('minutes_to_complete must be provided')
        try:
            iv = int(value)
        except Exception:
            raise ValueError('minutes_to_complete must be an integer')
        return iv