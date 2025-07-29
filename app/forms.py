from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class InputForm(FlaskForm):
    input_data = StringField('Enter URL / IP / Keyword', validators=[DataRequired()])
    submit = SubmitField('Scan')

