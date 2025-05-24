from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField
from wtforms.validators import DataRequired, Email, Regexp

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class CSRFForm(FlaskForm):
    """A basic form for CSRF protection"""
    pass

class RegistrationForm(FlaskForm):
    """Form for event registration"""
    name = StringField('Full Name', validators=[
        DataRequired(),
        Regexp(r'^[A-Za-z\s\'-]{2,50}$', message='Use only letters, spaces, hyphens, and apostrophes (2-50 characters)')
    ])
    email = StringField('Email Address', validators=[
        DataRequired(),
        Email(message='Invalid email address')
    ])
    student_id = StringField('Student ID', validators=[
        DataRequired(),
        Regexp(r'^\d{7}$', message='Must be 7 digits')
    ])
    event = SelectField('Select Event', validators=[DataRequired()], coerce=int) 