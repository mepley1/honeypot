#!/bin/sh
# Copy necessary application files to test server via SCP.
# Intended to be used after editing files, to save time updating existing files on live instance.
# Be very careful! Backup prod directory before using.
# The following will not be copied: user database, requests database, config.py, readme, license etc.

# Configure IP + auth
PROD_HOST=example.com
APP_PATH=/path/to/honeypot/honeypot
USERNAME=user
KEYFILE=~/.ssh/id_rsa

echo "Copying files to $PROD_HOST"
echo "${USERNAME}@${PROD_HOST}:${APP_PATH}/project/"

scp -i ${KEYFILE} db_initialize.py create-user.py wsgi.py requirements.txt reset-password.py ${USERNAME}@${PROD_HOST}:${APP_PATH}/
scp -i ${KEYFILE} -r ./project/static/ ${USERNAME}@${PROD_HOST}:${APP_PATH}/project/
scp -i ${KEYFILE} -r ./project/templates/ ${USERNAME}@${PROD_HOST}:${APP_PATH}/project/
scp -i ${KEYFILE} ./project/__init__.py ./project/auth.py ./project/main.py ./project/analysis.py ./project/models.py ./project/auto_report.py ${USERNAME}@${PROD_HOST}:${APP_PATH}/project/

# Don't overwrite current config on prod.
# Un-comment the following line ONLY if changing config.
#scp -i ${KEYFILE} ./project/config.py ${USERNAME}@${PROD_HOST}:${APP_PATH}/project/

# Restart app to prevent any issues after files changed
echo "Restarting service..."
ssh -i ${KEYFILE} ${USERNAME}@${PROD_HOST} "sudo systemctl restart honeypot.service"

echo "Finished."
