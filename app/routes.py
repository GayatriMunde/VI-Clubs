from flask import render_template, url_for, redirect, flash, request
from app import app, db, authorize
from app.forms import LoginForm, SRegistrationForm, CRegistrationForm, ResetPasswordRequestForm, ResetPasswordForm
from flask_login import current_user, login_user, logout_user
from app.models import User, Role, Member, Cord, Club, Category
from app.email import send_password_reset_email

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET','POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        return redirect(url_for('index'))
    return render_template('login.html', form=form, title="VI Clubs - Login!")

@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = SRegistrationForm()
    if form.validate_on_submit():
        mem = Member(name=form.name.data)
        role = Role.query.filter_by(name='member').first()
        user = User(username=form.username.data, email=form.email.data, member=mem)
        user.set_password(form.password.data)
        user.roles = [role]
        db.session.add(mem)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form, title="VI Clubs - Sign up!")

@app.route('/register_club', methods=['GET', 'POST'])
@authorize.has_role('admin')
def registerclub():
    form = CRegistrationForm()
    if form.validate_on_submit():
        categorytype = Category.query.filter_by(id=form.category.data).first()
        print(categorytype)
        club = Club(clubname=form.clubname.data, clubtype=categorytype)
        cord = Cord(cordname=form.cordname.data, collegeclub=club)
        role = Role.query.filter_by(name='cord').first()
        user = User(username=form.username.data, email=form.email.data, cord=cord)
        user.set_password(form.password.data)
        user.roles = [role]
        db.session.add(club, cord)
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!', 'success')
        return redirect(url_for('login'))
    return render_template('registerclub.html', form=form)

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = ResetPasswordRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is not None:
            send_password_reset_email(user)
            flash('Check your email for the instructions to reset your password', 'info')
            return redirect(url_for('login'))
        else:
            flash('No such email id registered. Please sign up.', 'warning')
            return redirect(url_for('register'))
    return render_template('forgot_password.html', form=form, title="VI Clubs")

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    user = User.verify_reset_password_token(token)
    if not user:
        return redirect(url_for('index'))
    form = ResetPasswordForm()
    if form.validate_on_submit():
        user.set_password(form.password.data)
        db.session.commit()
        flash('Your password has been reset.', 'success')
        return redirect(url_for('login'))
    return render_template('reset_password.html', form=form, title="VI Clubs")

@app.route('/clubs/<name>', methods=['GET', 'POST'])
def club(name):
    return render_template(name+'.html', title=name.upper()+" - VI Clubs")

@app.route('/forum')
def forum():
    return render_template('forum.html')