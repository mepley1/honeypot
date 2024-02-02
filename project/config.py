""" config.py - Make any configuration changes here to override defaults. """

import secrets

### Use a static SECRET_KEY value in production or else cookies won't stay valid.
### Is also used by Flask-WTF to generate CSRF tokens.
SECRET_KEY = secrets.token_hex()

### Session lifetime. Default: 86400
PERMANENT_SESSION_LIFETIME = 86400

### Enter your AbuseIPDB API key below, if you want to enable auto-reporting.
#ABUSEIPDB = '12345678'

### Restrict login to certain CIDR subnet. Default: 0.0.0.0/0 (v4) and ::/0 (v6) (allow anywhere).
### You should configure these to match whatever network you'll be logging in from, unless you
### want to collect wild login attempts - it is a honeypot after all.
ALLOWED_LOGIN_SUBNET = '0.0.0.0/0'
ALLOWED_LOGIN_SUBNET_V6 = '::/0'

################################################
### Database URI examples for various databases.
### Uncomment/configure one if using something other than the default SQLite db.

### SQLite (default)
SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite'

### MySQL
#SQLALCHEMY_DATABASE_URI = 'mysql://username:password@remote_server_ip/database_name'

### PostgreSQL
#SQLALCHEMY_DATABASE_URI = 'postgresql://username:password@remote_server_ip/database_name'
################################################
