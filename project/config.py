""" config.py - Make any extra flask app.config adjustments here to override defaults """

import secrets #You can comment out this import after you set a SECRET_KEY

SECRET_KEY = secrets.token_hex() #Use a static value in production or else cookies won't stay valid
PERMANENT_SESSION_LIFETIME = 86400
#ABUSEIPDB = '12345678' #Your AbuseIPDB API key
