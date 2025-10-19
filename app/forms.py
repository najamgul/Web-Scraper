# app/forms.py
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo

class InputForm(FlaskForm):
    input_data = TextAreaField(
        'Enter IOC', 
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter IP, URL, Domain, Hash, or Keyword", "rows": 3}
    )
    submit = SubmitField('Analyze Threat')


class LoginForm(FlaskForm):
    email = StringField(
        'Email', 
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "your.email@example.com"}
    )
    password = PasswordField(
        'Password', 
        validators=[DataRequired()],
        render_kw={"placeholder": "Enter your password"}
    )
    submit = SubmitField('Login')


class SignupForm(FlaskForm):
    email = StringField(
        'Email', 
        validators=[DataRequired(), Email()],
        render_kw={"placeholder": "your.email@example.com"}
    )
    password = PasswordField(
        'Password', 
        validators=[DataRequired(), Length(min=8, message="Password must be at least 8 characters")],
        render_kw={"placeholder": "Minimum 8 characters"}
    )
    confirm_password = PasswordField(
        'Confirm Password', 
        validators=[
            DataRequired(), 
            EqualTo('password', message="Passwords must match")
        ],
        render_kw={"placeholder": "Re-enter your password"}
    )
    submit = SubmitField('Sign Up')