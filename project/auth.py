""" Authentication routes & functions"""

import datetime #for logging
import sqlite3 #for logging bad logins
from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
from .models import User
from . import db

auth = Blueprint('auth', __name__)

def get_ip():
    """ Get client's IP from behind Nginx. Move this to a separate module later, so I can use it in the other blueprints. """
    if 'X-Real-Ip' in request.headers:
        client_ip = request.headers.get('X-Real-Ip') #get real ip from behind Nginx
    else:
        client_ip = request.remote_addr
    return client_ip

def insert_login_record(username, password):
    """ sql insert helper function, for logging auth attempts. """

    if 'X-Real-Ip' in request.headers:
        client_ip = request.headers.get('X-Real-Ip') #get real ip from behind Nginx
    else:
        client_ip = request.remote_addr
    login_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    #make the sqlite insert
    try:
        conn = sqlite3.connect('bots.db')
        c = conn.cursor()
        sql_query = """
            INSERT INTO logins
            (id,remoteaddr,username,password,time)
            VALUES (NULL, ?, ?, ?, ?);
            """
        data_tuple = (client_ip, username, password, login_time)
        c.execute(sql_query, data_tuple)
        conn.commit()
    except sqlite3.Error as e:
        print(f'Error inserting login record: {str(e)}')
    finally:
        conn.close()

@auth.context_processor
def inject_title():
    """Return the title to display on the navbar"""
    return {"SUBDOMAIN": 'lab.mepley', "TLD": '.com'}

# ROUTES

@auth.route('/login')
def login():
    """Route for /login GET requests, just display the login page"""
    if 'X-Real-Ip' in request.headers:
        client_ip = request.headers.get('X-Real-Ip')#Get real IP from behind Nginx proxy
    else:
        client_ip = request.remote_addr
    flash(f'Connecting from: {client_ip}', 'info')
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    """Grab the form data, authenticate and log in the user"""
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False #Remember Me checkbox

    user = User.query.filter_by(username=username).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):

        # Record the attempt in the database
        insert_login_record(username, password)
        print('Failed login attempt: ', username)

        flash('Invalid credentials.', 'errorn')
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # Record the successful login, but obviously don't log the password.
    # Can query where password = placeholder later, to query for successful logins.
    insert_login_record(username, '*** SUCCESSFUL LOGIN ***')
    print('Successful login: ', username)
    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.stats'))

@auth.route('/signup')
@login_required
def signup():
    return render_template('signup.html')

# Note: After creating an account, add @login_required decorator to signup_post so
# you must be logged in to create more accts.
@auth.route('/signup', methods=['POST'])
@login_required
def signup_post():
    """Validate and add user to database"""
    username = request.form.get('username')
    password = request.form.get('password')
    # if this returns a user, then username already exists in database
    user = User.query.filter_by(username=username).first()

    if user: # if user already exists, redirect back to signup page so user can try again
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
    """Log the user out & display home page"""
    logout_user()
    flash('Logged out.', 'successn')
    return redirect(url_for('main.index'))
