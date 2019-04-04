from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, BooleanField
from wtforms.validators import DataRequired, Length, Email, EqualTo, ValidationError
from flask_api.models import users

class RegistrationForm(FlaskForm):
    username = StringField('username',
                            validators=[DataRequired(),Length(min=2,max=20)])

    email = StringField('email',
                        validators=[DataRequired(), Email()])

    password = PasswordField('password', validators=[DataRequired()])
    confirm_password = PasswordField('confirm_password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

    def validate_username(self,username):
        user=users.query.filter_by(username=username.data).first()
        if(user):
            raise ValidationError('User already exists')
    def validate_email(self,email):
        email=users.query.filter_by(email=email.data.lower()).first()
        if(email):
            raise ValidationError('Email already has an account')

class LoginForm(FlaskForm):
    email = StringField('email',
                        validators=[DataRequired(), Email()])
    password = PasswordField('password', validators=[DataRequired()])
    remember = BooleanField('remember')
    submit = SubmitField('Log in')

class GenerateKeyForm(FlaskForm):
    submit = SubmitField('Generate Key')
