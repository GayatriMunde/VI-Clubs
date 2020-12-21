from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField, IntegerField, TextAreaField
from wtforms.validators import ValidationError, DataRequired, Email, EqualTo
from app.models import User

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()], render_kw={'class':'input'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'class':'input'})
    remember_me = BooleanField('Remember me')
    submit = SubmitField("Log in", render_kw={'class':'mbtn'})

class SRegistrationForm(FlaskForm):
    name = StringField('Your Name', validators=[DataRequired()], render_kw={'class':'input'})
    #grno = IntegerField('GR No.', validators=[DataRequired()], render_kw={'class':'input'})
    username = StringField('Username', validators=[DataRequired()], render_kw={'class':'input'})
    email = StringField('Email id', validators=[DataRequired(), Email()], render_kw={'class':'input'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'class':'input'})
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={'class':'input'})
    submit = SubmitField('Sign up', render_kw={'class':'mbtn'})

    def validate_username(self, username):
        stud = User.query.filter_by(username=username.data).first()
        if stud is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        stud = User.query.filter_by(email=email.data).first()
        if stud is not None:
            raise ValidationError('Email address already registered.')
    
    '''def validate_grno(self, grno):
        stud = Student.query.filter_by(grno=grno.data).first()
        if stud is not None:
            raise ValidationError('GR No. already registered.')'''

class CRegistrationForm(FlaskForm):
    clubname = StringField('Club Name', validators=[DataRequired()], render_kw={'class':'input'})
    cordname = StringField('Coordinator Name', validators=[DataRequired()], render_kw={'class':'input'})
    category = SelectField('Select Category', validators=[DataRequired()], choices=[(1,'Technical'), (2,'Non-Techincal')], render_kw={'class':'input'})
    username = StringField('Username', validators=[DataRequired()], render_kw={'class':'input'})
    email = StringField('Club Email id', validators=[DataRequired(), Email()], render_kw={'class':'input'})
    password = PasswordField('Password', validators=[DataRequired()], render_kw={'class':'input'})
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')], render_kw={'class':'input'})
    submit = SubmitField('Sign up', render_kw={'class':'mbtn'})

    def validate_username(self, username):
        cord = User.query.filter_by(username=username.data).first()
        if cord is not None:
            raise ValidationError('Please use a different username.')

    def validate_email(self, email):
        cord = User.query.filter_by(email=email.data).first()
        if cord is not None:
            raise ValidationError('Email address already registered.')

class ResetPasswordRequestForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    password2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Change Password')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = StringField('Email', validators=[DataRequired(), Email()])
    m_type = SelectField('Choose type', validators=[DataRequired()], choices=[(1,'Query'), (2,'Suggestion'), (3,'Complaint')])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit')