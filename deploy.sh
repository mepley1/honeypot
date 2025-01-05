#!/bin/sh
# Copy necessary application files to directory on prod server via SCP.
# Intended to be used after editing files, to easily update existing files on prod.
# Be very careful! Backup prod directory before using.
# The following will not be copied: user database, requests database, config.py, readme, license etc.

# Configure IP + auth
PROD_HOST=example.com
USERNAME=user
KEYFILE=~/.ssh/id_rsa

echo "Copying files..."
echo "Production host: $PROD_HOST"

scp -i $KEYFILE db_initialize.py create-user.py wsgi.py requirements.txt reset-password.py $USERNAME@$PROD_HOST:/root/honeypot/honeypot/
scp -i $KEYFILE -r ./project/static/ $USERNAME@$PROD_HOST:/root/honeypot/honeypot/project/
scp -i $KEYFILE -r ./project/templates/ $USERNAME@$PROD_HOST:/root/honeypot/honeypot/project/
scp -i $KEYFILE ./project/__init__.py ./project/auth.py ./project/main.py ./project/analysis.py ./project/models.py ./project/auto_report.py $USERNAME@$PROD_HOST:/root/honeypot/honeypot/project/

# Don't overwrite current config on prod.
# Un-comment the following line ONLY if changing config.
#scp -i $KEYFILE ./project/config.py $USERNAME@$PROD_HOST:/root/honeypot/honeypot/project/

echo "Finished."
