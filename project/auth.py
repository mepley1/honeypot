from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
from .models import User

from . import db

auth = Blueprint('auth', __name__)

@auth.context_processor
def inject_title():
    return dict(SUBDOMAIN="lab.mepley", TLD=".com")

@auth.route('/login')
def login():
    if 'X-Real-Ip' in request.headers:#need to get real IP from behind Nginx proxy
        clientIP = request.headers.get('X-Real-Ip')
    else:
        clientIP = request.remote_addr
    flash('Connecting from: ' + clientIP)
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    #login code goes here
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(username=username).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Invalid credentials.', 'errorn')
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.stats'))

@auth.route('/signup')
@login_required
def signup():
    return render_template('signup.html')

# After creating an account, add @login_required decorator to signup_post so you must be logged in to create more accts
@auth.route('/signup', methods=['POST'])
@login_required
def signup_post():
    # code to validate and add user to database goes here
    username = request.form.get('username')
    password = request.form.get('password')

    user = User.query.filter_by(username=username).first() # if this returns a user, then the email already exists in database

    if user: # if a user is found, we want to redirect back to signup page so user can try again
        flash('Username already exists', 'errorn')
        return redirect(url_for('auth.signup'))
    
    # create a new user with the form data. Hash the password so the plaintext version isn't saved.
    new_user = User(username=username, password=generate_password_hash(password))

    # add the new user to the database
    db.session.add(new_user)
    db.session.commit()

    flash('User created successfully.', 'successn')
    return redirect(url_for('auth.login'))

@auth.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'successn')
    return redirect(url_for('main.index'))