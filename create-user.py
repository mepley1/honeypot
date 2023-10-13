#!/usr/bin/env python3
""" Create a user account and add it to the database. Usage: python create-user.py <username> """

import argparse
from werkzeug.security import generate_password_hash, check_password_hash
from project import create_app, db, models

app = create_app()

# parse command line arguments
parser = argparse.ArgumentParser(description = 'Create user account.')
parser.add_argument('username', type = ascii, nargs = '?', help = 'Username for new account.')
args = parser.parse_args()

# Create a user account
def create_new_user():
    """ Prompt for creds, create new user and add to db """

    if args.username:
        user_username = args.username
    else:
        user_username = input('Username for new account:\n')

    with app.app_context():
        # if this returns a user, then username already exists in database
        user = models.User.query.filter_by(username=user_username).first()

        if user:
            print('Error: Username already exists.\n')
            quit()

        # Prompt for a password to use
        user_password = input(str('Password for new account:\n'))

        # create a new user with the form data. Hash the password so the plaintext version isn't saved.
        new_user = models.User(username=user_username, password=generate_password_hash(user_password))

        # add the new user to the database
        db.session.add(new_user)
        db.session.commit()

        print('User created successfully.')

if __name__ == '__main__':
    create_new_user()
