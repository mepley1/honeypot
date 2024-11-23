# Webpot

[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fmepley1%2Fhoneypot&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false)](https://hits.seeyoufarm.com)

<img src="https://www.abuseipdb.com/contributor/62444.svg" alt="AbuseIPDB contributor badge" width="150" />

A simple HTTP honeypot + analysis webapp for capturing and analyzing HTTP requests + auto reporting. 
Stores request data in a SQLite database and includes some stats views for easier analysis of wild bot(net)/scanner traffic. Includes a catch-all route to catch requests using any HTTP method for (almost) any URI.

Very much a work in progress. 

[Live Demo](https://x2.mepley.com/stats) Note: May not be active at any given time. 
Demo login: 
user: `demo` 
pw: `0xDEADBEEF` 

## To run locally for testing/development:

Create and activate a venv:

`cd honeypot`

`python3 -m venv venv`

`source venv/bin/activate`

Install required Python modules in the venv:

`pip install -r requirements.txt`

Configuration, find in config.py. Can also use environment variables prepended with `FLASK_`.
1. Edit the `SECRET_KEY` in `config.py` if you want cookies to work, or export it as an environment variable: `export FLASK_SECRET_KEY='0123456789'` (To generate a good key, in a Python shell run `secrets.token_hex()`)
2. `ABUSEIPDB='0123456789'` - Set your AbuseIPDB API key, for auto-reporting. If not set, nothing will be reported to AbuseIPDB.
3. `ALLOWED_LOGIN_SUBNET` - Restrict logins to only this subnet. (A single IP works as well)
4. `ALLOWED_LOGIN_SUBNET_V6` - Same, for an IPv6 subnet.
5. `EXEMPT_SUBNETS` - IPs in these subnets won't be reported to AbuseIPDB.
6. `CUSTOM_SIGNATUES` and `CUSTOM_REGEX` - Custom strings or regex patterns to search for in received requests.
7. `SQLALCHEMY_DATABASE_URI` - URI for the user accounts db. Default is a SQLite db file in /instance. (User accounts and HTTP request data are stored in two separate databases.)

Initialize users database:

`python db_initialize.py`

Create a login:

`python create-user.py`

Run the app:

`export FLASK_DEBUG=True` - (Optional) To turn on Flask debug mode if you want/need it for development. (DO NOT use debug mode in production, as with any Flask app)

`flask run`

Then point your browser to http://localhost:5000 and log in.

# Features
- Catch-all route to catch requests for any URI.
- Stats views to filter by IP/method/user-agent/URL/query etc. - click on any piece of data that becomes a link to query for matching records.
- Toggle display/hide data columns.
- Now has proper auth + remember me (set `SECRET_KEY` in `config.py`)
- Restrict login to specified CIDR subnet. (`ALLOWED_LOGIN_SUBNET` in `config.py`)
- Auto reporting to AbuseIPDB with somewhat extendable "detection rules."; configurable exempt subnets + custom rules.
- Search for arbitrary strings in request path/headers/body etc.
- Optional/bonus: If you configure your DNS server to return the honeypot server's IP for blocked requests instead of NXDOMAIN, to gain some extra visibility- though this can cause odd failures in some apps.

# Auto-reporting + Detection rules
The auto-reporting will report to AbuseIPDB any request that matches the defined "detection rules."

To enable auto-reporting, copy your AbuseIPDB API key into the ABUSEIPDB value in `config.py`, or create an environment variable `export FLASK_ABUSEIPDB=<your-api-key>`. The application will check for the existence of either the environment variable or the ABUSEIPDB line in config.py, and if it finds either, then reports will be submitted automatically. If no key is configured, it will still check each request against the detection rules, but will skip the submit_report function.

To understand how the rules are structured, see `auto_report.py`. Each detection rule is little more than a function that returns a boolean True/False if certain strings are found or regex patterns are matched in the various properties of the request object. There's probably a more efficient way to do this, but this works well enough for my use case; if I go much further here then I'd just be re-inventing the wheel that Fail2Ban/Snort/Suricata and many other tools already do far better. I've tried to keep the rules somewhat conservative, at least not reporting requests for /, and only report requests that are known to be malicious; while avoiding reporting known security researchers/scanners. You can add your own regex patterns or strings to match in config.py; add them to either CUSTOM_REGEX or CUSTOM_SIGNATURES respectively.

# Deploying with Gunicorn+Nginx+Systemd, see deployment.md 

An example systemd service unit file is included, see `/etc/systemd/system/honeypot.service`. After configuring the service unit, place it in your systemd units directory (on Debian `/etc/systemd/system/`). Then you can run it as a systemd unit. Use `sudo systemctl enable honeypot.service && sudo systemctl start honeypot.service` to enable and start it; `journalctl -u honeypot.service` with any other journalctl options to view logs. By default it will produce a lot of logs, at least a few lines per request; if you want less you can change the log level in `__init__.py`. `DEBUG` (default), `INFO` and `ERROR` are the only levels I've used much in the code, with one or two `WARNING`.
If serving behind Nginx/other reverse proxy, be mindful of any configuration that affects the request headers; analysis can be done most accurately if all headers are passed to the honepot as-is.
To-do: Deployment guide. Include Nginx proxy conf & systemd service unit. 

# Extra scripts for testing
`test-post-request.py` | Sends a POST request to localhost:5000 for testing. Accepts up to 2 parameters, which are used as the request body. For ex., to send `{'key1', 'value1'}` you would run `python test-post-request.py key1 value1`. If no parameters input then some default data is used. Can also do something like `./test-send-request.py $(head -c 32 /dev/urandom)` in a Bash shell.

`test-highvolume.py` | Send a bunch of GET + POST requests to localhost:5000, for testing/generating some data.

`test-post-bad-data.py` | POST some random data, single request, with no Content-Type specified.

`create-venv.sh` | Just creates a venv named `venv` in the current directory.

`deploy.sh` | This is NOT for production deployment, it only copies the main app files to another machine for development purposes - I use it to copy over new versions of the Flask blueprints to my "production" server where the app is already deployed, as an "update" script of sorts.

# Notes/issues:
- Will have to force Werkzeug=2.3.0 for a bit in requirements.txt until flask-login release a version compatible with Werkzeug 3.
- When refreshing stats page after toggling column views, checkboxes get out of sync; to fix, either force refresh (Ctrl+F5) or click the navbar link again. Need a better way of hiding columns.
- Querying for records by POST request body fails to find anything in some cases due to encoding discrepancies.

# To-do:
- Standardize error responses.
- Rewrite detection rules using regex instead of string searches. Move the bigger lists to a separate file to import at run time rather than defining each list inside the functions- should greatly improve performance, and will allow for easier custom rules.
- Deployment guide - deployment.md - Include Nginx vhost conf file, systemd service unit example
- Some graphs/charts - do some analysis + visualization on top IPs/paths/location data/etc.
- Per-account login IP whitelist.
- Separate stats routes into another blueprint
