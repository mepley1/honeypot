""" Authentication routes & functions"""

import datetime #for logging
import logging
import sqlite3 #for logging bad logins
from flask import Blueprint, current_app, render_template, redirect, url_for, request, flash, abort
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user
import ipaddress
from .models import User
from . import db

auth = Blueprint('auth', __name__)

# A couple helper functions
def get_ip():
    """ Get client's IP from behind Nginx/Cloudflare. + stop repeating this code.
    Move this to a separate module later, so I can use it in the other blueprints. """
    if 'Cf-Connecting-Ipv6' in request.headers:
        client_ip = request.headers.get('Cf-Connecting-Ipv6')
    elif 'Cf-Connecting-Ip' in request.headers:
        client_ip = request.headers.get('Cf-Connecting-Ip') #will be there if site is behind cloudflare
    elif 'X-Real-Ip' in request.headers:
        client_ip = request.headers.get('X-Real-Ip') #get real ip from behind Nginx
    elif 'X-Forwarded-For' in request.headers:
        client_ip = request.headers.get('X-Forwarded-For')
    else:
        client_ip = request.remote_addr
    return client_ip

def insert_login_record(username, password):
    """ sql insert helper function, for logging auth attempts. """

    client_ip = get_ip()
    login_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Log the attempt in the logins table of database
    try:
        with sqlite3.connect('bots.db') as conn:
            c = conn.cursor()
            sql_query = """
                INSERT INTO logins
                (id,remoteaddr,username,password,time)
                VALUES (NULL, ?, ?, ?, ?);
                """
            data_tuple = (client_ip, username, password, login_time)
            c.execute(sql_query, data_tuple)
            conn.commit()
            c.close()
        conn.close()
    except sqlite3.Error as e:
        logging.error(f'Error inserting login record: {str(e)}')

def is_allowed(ip_to_check):
    """ Check whether the client IP address is in the allowed login subnet. """
    #First check whether allowed subnet is configured.
    if not current_app.config.get('ALLOWED_LOGIN_SUBNET') and not current_app.config.get('ALLOWED_LOGIN_SUBNET_V6'):
        return False #If no subnet configured, deny all.

    if current_app.config.get('ALLOWED_LOGIN_SUBNET'):
        ALLOWED_LOGIN_SUBNET = ipaddress.IPv4Network(current_app.config["ALLOWED_LOGIN_SUBNET"])
    if current_app.config.get('ALLOWED_LOGIN_SUBNET_V6'):
        ALLOWED_LOGIN_SUBNET_V6 = ipaddress.IPv6Network(current_app.config["ALLOWED_LOGIN_SUBNET_V6"])
    # ipaddress.ip_address() will work for both v4+v6 in this case, as opposed to IPv4Address()/IPv6Address(),
    # so no need for an isinstance() check; ip_address() will return the proper type.
    ip_conv = ipaddress.ip_address(ip_to_check)
    # If client IP is in allowed subnet, return True
    if ip_conv in ALLOWED_LOGIN_SUBNET or ip_conv in ALLOWED_LOGIN_SUBNET_V6:
        return True
    else:
        return False

@auth.context_processor
def inject_title():
    """Return the title to display on the navbar"""
    return {"SUBDOMAIN": 'lab.mepley', "TLD": '.com'}

# ROUTES

@auth.route('/login')
def login():
    """Route for /login GET requests, just display the login page"""
    client_ip = get_ip() #get user's ip to display
    if is_allowed(client_ip):
        flash('IP found in whitelist.', 'info')
    else:
        flash('Login disallowed: IP address not in whitelist.', 'errorn')
    flash(f'Connecting from: {client_ip}', 'info')
    return render_template('login.html')

@auth.route('/login', methods=['POST'])
def login_post():
    """Grab the form data, authenticate and log in the user"""
    username = request.form.get('username')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False #Remember Me checkbox

    user = User.query.filter_by(username=username).first()

    # If IP isn't in allowed login subnet, record the attempt and redirect.
    if not is_allowed(get_ip()):
        insert_login_record(username, password)
        logging.info(f'Blocked login attempt (IP not whitelisted) from {get_ip()}: {username}')
        return redirect(url_for('auth.login'))

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):

        # Record the attempt in the database
        insert_login_record(username, password)
        logging.info(f'Failed login attempt from {get_ip()}: {username}')

        flash('Invalid credentials.', 'errorn')
        return redirect(url_for('auth.login')) # if user doesn't exist or password is wrong, reload page

    # Record the successful login, but obviously don't log the password.
    # Can query where password = placeholder later, to query for successful logins.
    insert_login_record(username, '*** SUCCESSFUL LOGIN ***')
    logging.info(f'Successful login from {get_ip()}: {username}')
    # if the above check passes, then we know the user has the right credentials, so log them in
    login_user(user, remember=remember)
    return redirect(url_for('main.stats'))

@auth.route('/signup')
@login_required
def signup():
    return render_template('signup.html')

# Note: After creating an account, add @login_required decorator to signup_post so
# you must be logged in to create more accts.
## Note: I have the create-user.py script now, so this endpoint isn't needed anymore
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
