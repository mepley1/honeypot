""" Authentication routes & functions"""
# Editing branch

import datetime #for logging
import sqlite3 #for logging bad logins
from flask import Blueprint, render_template, redirect, url_for, request, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
from .models import User
from . import db

auth = Blueprint('auth', __name__)

@auth.context_processor
def inject_title():
    """Return the title to display on the navbar"""
    #return dict(SUBDOMAIN="lab.mepley", TLD=".com")
    return {"SUBDOMAIN": 'lab.mepley', "TLD": '.com'}

@auth.route('/login')
def login():
    """Route for /login GET requests, just display the login page"""
    if 'X-Real-Ip' in request.headers:
        clientIP = request.headers.get('X-Real-Ip')#Get real IP from behind Nginx proxy
    else:
        clientIP = request.remote_addr
    flash('Connecting from: ' + clientIP)
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
        """If credentials incorrect, log the attempt in the Logins table of bots.db.
        Be careful doing this, can easily end up logging typos of real credentials.
        Might move this section lower and just log all logins, with placeholders for creds on success.
        i.e. just save the username + IP + time. """

        if 'X-Real-Ip' in request.headers:
            clientIP = request.headers.get('X-Real-Ip') #get real ip from behind Nginx
        else:
            clientIP = request.remote_addr
        loginTime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        # begin SQL ********************
        # Note: Rewrite the sql inserts as a helper function in another module or the app factory
        # then import that module, so I can stop repeating it.
        conn = sqlite3.connect("bots.db")
        c = conn.cursor()
        sqlQuery = """INSERT INTO logins
            (id,remoteaddr,username,password,time)
            VALUES (NULL, ?, ?, ?, ?);"""
        dataTuple = (clientIP, username, password, loginTime)
        c.execute(sqlQuery, dataTuple)
        conn.commit()
        conn.close()
        #  END SQL *********************

        flash('Invalid credentials.', 'errorn')
        return redirect(url_for('auth.login')) # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect(url_for('main.stats'))

@auth.route('/signup')
#@login_required
def signup():
    return render_template('signup.html')

# Note: After creating an account, add @login_required decorator to signup_post so
# you must be logged in to create more accts.
@auth.route('/signup', methods=['POST'])
#@login_required
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
    flash('Logged out successfully.', 'successn')
    return redirect(url_for('main.index'))
