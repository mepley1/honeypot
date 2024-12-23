""" config.py - Make any configuration changes here to override defaults. """

import secrets

### Use a static SECRET_KEY value in production or else cookies won't stay valid.
### Is also used by Flask-WTF to generate CSRF tokens.
SECRET_KEY = secrets.token_hex()

### Session lifetime. Default: 86400
PERMANENT_SESSION_LIFETIME = 86400

### Site title to display on the navbar. Default: x2.mepley.com
SITE_TITLE_SUBDOMAIN = 'x2.mepley'
SITE_TITLE_TLD = '.com'

### Enter your AbuseIPDB API key below, if you want to enable auto-reporting. Default: disabled
#ABUSEIPDB = '12345678'

### hCaptcha site key + secret, for login form captcha. See https://dashboard.hcaptcha.com/settings
### To disable hCaptcha challenges, comment-out these lines or set value = False.
#HCAPTCHA_SITE_KEY = '12345678'
#HCAPTCHA_SECRET = '12345678'

### Restrict login to certain CIDR subnet. Default: 0.0.0.0/0 (v4) and ::/0 (v6) (allow anywhere).
### Configure these to match whatever network you'll be logging in from, unless you
### want to collect wild login attempts - it is a honeypot after all.
ALLOWED_LOGIN_SUBNET = '0.0.0.0/0'
ALLOWED_LOGIN_SUBNET_V6 = '::/0'

### Do not submit AbuseIPDB reports for IP addresses in any of the following subnets. 
### Default: Any private/link-local/loopback
EXEMPT_SUBNETS = [
    '10.0.0.0/8', #IPv4 private
    '172.16.0.0/12', #IPv4 private
    '192.168.0.0/16', #IPv4 private
    '169.254.0.0/16', #APIPA
    '127.0.0.0/8', #IPv4 loopback
    'fc00::/7', # IPv6 ULA
    'fe80::/10', # IPv6 link-local
    '::1/128', # IPv6 loopback
]

### If False, all failed login attempts will be logged, including the password that was used.
### This creates a risk of exposing passwords if i.e. you mistype your username.
### If the following option is set to True, then no passwords will be logged at all. (Default: True)
DONT_LOG_PASSWORDS = True

### Configure the main catch-all route to return either an HTML page, 
### the client IP, or just a 200 status code.
### Returning only the client IP or status code may reduce being quickly fingerprinted
### as an instance of this honeypot, at least if no application routes are requested.
### Values: 1 = HTML page (default), 2 = IP, 3 = Status code
INDEX_RESPONSE_TYPE = 1

################################################
### Database URI examples for various database systems. Default: SQLite (/honeypot/instance/db.sqlite)
### Uncomment/configure one if using something else. Users db only.

### SQLite (default)
SQLALCHEMY_DATABASE_URI = 'sqlite:///db.sqlite'

### MySQL
#SQLALCHEMY_DATABASE_URI = 'mysql://username:password@remote_server_ip/database_name'

### PostgreSQL
#SQLALCHEMY_DATABASE_URI = 'postgresql://username:password@remote_server_ip/database_name'
################################################

################################################
### Custom signatures
### This list is used in the custom detections rule. Each string in this list will be checked
### for in the request path, queries, body, and header values. If the string is found, the
### IP address will be reported. Case insensitive. Must be a valid Python list.
CUSTOM_SIGNATURES = [
    '/test/example1',
]

### Regex version, for more precise matching. Format as a list of regex patterns.
CUSTOM_REGEX = [
    r'./test/regex$',
]
################################################
