# app/models.py
from datetime import datetime
import uuid
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from . import db, login  # 使用相对导入

# 关联表，用于多对多关系（共享列表）
shared_list = db.Table('shared_list',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('list_id', db.Integer, db.ForeignKey('list.id'))
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    lists = db.relationship('List', backref='owner', lazy='dynamic')
    shared_lists = db.relationship('List', secondary=shared_list, backref='shared_with', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
   
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
   
    def __repr__(self):
        return f'<User {self.username}>'

class List(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    memos = db.relationship('Memo', backref='list', lazy='dynamic')
    is_shared = db.Column(db.Boolean, default=False)
    share_link = db.Column(db.String(36), unique=True, nullable=True)

    def generate_share_link(self):
        while True:
            link = str(uuid.uuid4())
            if not List.query.filter_by(share_link=link).first():
                self.share_link = link
                break

    def __repr__(self):
        return f'<List {self.name}>'

class Memo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128), nullable=False)
    content = db.Column(db.Text, nullable=True)
    list_id = db.Column(db.Integer, db.ForeignKey('list.id'))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)

    def __repr__(self):
        return f'<Memo {self.title}>'

@login.user_loader
def load_user(id):
    return User.query.get(int(id))
