"""
Reset a user account's password and update it in the database.
Usage: python reset-password.py <username>
"""

import argparse
from werkzeug.security import generate_password_hash, check_password_hash
from project import create_app, db, models

app = create_app()

# parse command line arguments
parser = argparse.ArgumentParser(description='Reset user account password.')
parser.add_argument('username', nargs='?', help='Username for the account.')
args = parser.parse_args()

# Reset a user account's password
def reset_user_password():
    """ Reset user's password and update it in the database """

    if args.username:
        user_username = args.username
    else:
        user_username = input('Username for the account:\n')

    with app.app_context():
        # Fetch the user from the database
        user = models.User.query.filter_by(username=user_username).first()

        if user is None:
            print('Error: User not found.\n')
            quit()

        # Prompt for the current password
        while True:
            current_password = input('Enter CURRENT password:\n')

            if check_password_hash(user.password, current_password):
                break
            else:
                print("Error: Incorrect password, try again.")

        # Prompt for the new password
        while True:
            new_password = input('New password:\n')
            confirm_password = input('Confirm new password:\n')

            if new_password == confirm_password:
                break
            else:
                print("Error: Passwords do not match. Please try again.")

        # Update the user's password in the database
        user.password = generate_password_hash(new_password)
        db.session.commit()

        print('Password reset successfully.')

if __name__ == '__main__':
    reset_user_password()
