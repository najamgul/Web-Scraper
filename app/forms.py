from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class InputForm(FlaskForm):
    input_data = StringField("Keyword, IP, URL, or domain", validators=[DataRequired()])
    submit = SubmitField("Search")
