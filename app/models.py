from datetime import datetime
from app import db, login, app
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin
from flask_authorize import RestrictionsMixin, AllowancesMixin, PermissionsMixin
from time import time
import jwt

UserRole = db.Table(
    'user_role', db.Model.metadata,
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

class User(UserMixin, db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=False, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    minfo_id = db.Column(db.Integer, db.ForeignKey('member.id'), unique=True, nullable=True)
    cinfo_id = db.Column(db.Integer, db.ForeignKey('cord.id'), unique=True, nullable=True)
    roles = db.relationship('Role', secondary=UserRole)

    def __repr__(self):
        return '<User {}>'.format(self.username)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_reset_password_token(self, expires_in=600):
        return jwt.encode(
            {'reset_password': self.id, 'exp': time() + expires_in},
            app.config['SECRET_KEY'], algorithm='HS256').decode('utf-8')

    @staticmethod
    def verify_reset_password_token(token):
        try:
            id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return
        return User.query.get(id)

class Role(db.Model, AllowancesMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False, unique=True)

class Member(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(32))
    user_info = db.relationship('User', backref='member', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.name)

class Cord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    cordname = db.Column(db.String(32))
    club_id = db.Column(db.Integer, db.ForeignKey('club.id'))
    user_info = db.relationship('User', backref='cord', lazy='dynamic')

    def __repr__(self):
        return '<User {}>'.format(self.cordname)

class Club(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    clubname = db.Column(db.String(64), index=True, unique=True)
    categoryid = db.Column(db.Integer, db.ForeignKey('category.id'))
    cords = db.relationship('Cord', backref='collegeclub', lazy='dynamic')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(16)) 
    clubs = db.relationship('Club', backref='clubtype', lazy='dynamic')

@login.user_loader
def load_user(id):
    return User.query.get(int(id))
