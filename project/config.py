"""Make any extra flask app.config adjustments here to override defaults """

#import secrets

SECRET_KEY = secrets.token_hex() #Use a static value in production or else cookies won't stay valid
PERMANENT_SESSION_LIFETIME = 86400
