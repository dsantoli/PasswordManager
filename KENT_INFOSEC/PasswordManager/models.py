from config import db
from datetime import datetime

class User(db.Model):
    __tablename__ = 'User'
    id = db.Column('ID', db.Integer, primary_key=True)  # Maps 'ID' in DB to 'id' in Python
    username = db.Column('Username', db.String(80), unique=True, nullable=False)
    password = db.Column('Password', db.String(120), nullable=False)
    password_entries = db.relationship('PasswordEntry', backref='user', lazy='dynamic')

class PasswordEntry(db.Model):
    __tablename__ = 'PasswordEntry'
    id = db.Column('ID', db.Integer, primary_key=True)
    user_id = db.Column('UserID', db.Integer, db.ForeignKey('User.ID'), nullable=False)
    website = db.Column('Website', db.String(120), nullable=False)
    username = db.Column('Username', db.String(80), nullable=False)
    encrypted_password = db.Column('EncryptedPassword', db.String(120), nullable=False)
    salt = db.Column('Salt', db.String(120), nullable=False)
    timestamp = db.Column('Timestamp', db.DateTime, default=datetime.now)

    