""" config.py - Make any configuration adjustments here to override defaults. """

import secrets #You can comment out this import after you set a SECRET_KEY

# Use a static SECRET_KEY value in production or else cookies won't stay valid.
SECRET_KEY = secrets.token_hex()

# Session lifetime. Default: 86400
PERMANENT_SESSION_LIFETIME = 86400

# Enter your AbuseIPDB API key below, if you want to enable auto-reporting.
#ABUSEIPDB = '12345678'

# Restrict login to a certain CIDR subnet. Default: 0.0.0.0/0
ALLOWED_LOGIN_SUBNET = '0.0.0.0/0'
