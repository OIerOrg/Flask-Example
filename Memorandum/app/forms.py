# app/forms.py

from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length

class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=1, max=64)])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')

class RegistrationForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=1, max=64)])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('注册')

class ListForm(FlaskForm):
    list_name = StringField('新建列表', validators=[DataRequired(), Length(min=1, max=128)])
    submit = SubmitField('创建')

class MemoForm(FlaskForm):
    title = StringField('标题', validators=[DataRequired(), Length(min=1, max=128)])
    content = TextAreaField('内容')
    submit = SubmitField('保存')
class EmptyForm(FlaskForm):
    submit = SubmitField('提交')
