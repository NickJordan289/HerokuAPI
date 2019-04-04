from flask_api import db, login_manager # the app running this module
from flask_login import UserMixin
import datetime, time # for key expiration

@login_manager.user_loader
def load_user(user_id):
    return users.query.get(int(user_id))

class users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    image_file = db.Column(db.String(20), nullable=False, default='default.jpg')

    api_key = db.relationship('apikeys', backref='owner', lazy=True) #list? not obj

    def __repr__(self):
        return f"users('{self.username}', '{self.email}, '{self.image_file}')"

class apikeys(db.Model):
    key = db.Column(db.String(36), primary_key=True, nullable=False, default='')
    expiration = db.Column(db.Integer, nullable=False, default=-1)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, default='-1')
    active = db.Column(db.Boolean, default=False)

    def __repr__(self):
        return f"apikeys('{self.key}', '{self.expiration}, '{self.user_id}', '{self.active}')"
