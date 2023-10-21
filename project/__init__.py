""" The linter says even an __init__.py should have a docstring. """

import secrets
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()

def create_app():
    """ Create the app and register blueprints + loginmanager.  """
    app = Flask(__name__)

    # Override these in config.py if you want, just making some defaults.
    # To-do: check for existence of FLASK_SECRET_KEY envvar first, then config.py,
    # then fall back to secrets.token_hex()
    app.config['SECRET_KEY'] = secrets.token_hex()
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
    app.config['PERMANENT_SESSION_LIFETIME'] = 86400
    app.config.from_pyfile('config.py')
    app.config.from_prefixed_env()

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Must be logged in to view this page.'
    login_manager.login_message_category = 'errorn'
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

    # blueprint for auth routes in our app
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth parts of app
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    logging.basicConfig(encoding='utf-8', level=logging.INFO)

    return app
