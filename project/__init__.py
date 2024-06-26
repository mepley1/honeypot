""" The linter says even an __init__.py should have a docstring. """

import secrets
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf.csrf import CSRFProtect
from flask_caching import Cache

# init SQLAlchemy so we can use it later in our models
db = SQLAlchemy()

cache = Cache()

def create_app():
    """ Create the app and register blueprints + loginmanager.  """
    app = Flask(__name__)

    # Let env vars override anything in config.py
    app.config.from_pyfile('config.py')
    app.config.from_prefixed_env()

    # CSRF tokens via Flask-WTF
    csrf = CSRFProtect()
    csrf.init_app(app)

    db.init_app(app)

    # Register loginmanager
    login_manager = LoginManager()
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Must be logged in to view this page.'
    login_manager.login_message_category = 'errorn'
    login_manager.init_app(app)

    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        # Since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

    # blueprint for auth routes
    from .auth import auth as auth_blueprint
    app.register_blueprint(auth_blueprint)

    # blueprint for non-auth routes
    from .main import main as main_blueprint
    app.register_blueprint(main_blueprint)

    # blueprint for analysis etc routes
    from .analysis import analysis as analysis_blueprint
    app.register_blueprint(analysis_blueprint)

    # Exempt the catch-all route (/) from CSRF protection, otherwise no POST requests will hit it.
    from .main import index
    csrf.exempt(index)

    # Logging config
    logging.basicConfig(encoding='utf-8', level=logging.DEBUG)

    # initialize cache
    app.config['CACHE_TYPE'] = 'SimpleCache'
    cache.init_app(app)

    # Custom jinja filter using quote_plus, to solve my issue with encoding discrepancies
    # when querying body column.
    from urllib.parse import quote_plus
    app.jinja_env.filters['quote_plus'] = lambda u: quote_plus(u)

    return app
