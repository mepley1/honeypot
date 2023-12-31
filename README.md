# Webpot
A simple HTTP honeypot for capturing and viewing HTTP requests + auto reporting. 
Stores request data in a SQLite database and includes some stats views for easy analysis of all the bot traffic hitting your web services. Includes a catch-all route to catch requests using any HTTP method for any URI.

Very much a work in progress. 

[Live Demo](http://lab.mepley.com/) Note: May not be active or up to date at any given time. Demo login: user `demo` pw `0xDEADBEEF`

## To run locally:

Create and activate a venv:

`python3 -m venv venv`

`source venv/bin/activate`

Install required Python modules in the venv:

`pip install -r requirements.txt`

Configuration (Set either in config.py or as environment variables prepended with _FLASK):
1. Edit the `SECRET_KEY` in `config.py` if you want cookies to work, or export it as an environment variable: `export FLASK_SECRET_KEY=0123456789` (To generate a good key, in a Python shell run `secrets.token_hex()`)
2. `export FLASK_ABUSEIPDB=0123456789` - Set your AbuseIPDB API key, for auto-reporting. If not set, nothing will be reported to AbuseIPDB.
3. `export FLASK_DEBUG=true` - To turn on Flask debug mode if you want/need it for development.

Initialize database:

`python db_initialize.py`

Create a login:

`python create-user.py <username>`

Run the app:

`export FLASK_APP=project`

`flask run`

Then point your browser to http://localhost:5000 and log in.

# Features
- Catch-all route to catch requests for any URI
- Stats views to filter by IP/method/user-agent/URL/query - click on any piece of data that becomes a link to query for matching records.
- Toggle display/hide data columns.
- Now has proper auth + remember me (must set `SECRET_KEY` in `config.py`/ env vars.)
- Auto reporting with extendable "detection rules."

# Auto-reporting + Detection rules
The auto-reporting will report to AbuseIPDB any request that matches the defined "detection rules."

To enable auto-reporting, copy your AbuseIPDB API key into the ABUSEIPDB value in `config.py`, or create an environment variable `export FLASK_ABUSEIPDB=<your-api-key>`. The application will check for the existence of either the environment variable or the ABUSEIPDB line in config.py, and if it finds either, then reports will be submitted automatically. If no key is configured, it will still check each request against the detection rules, but will skip the submit_report function.

To understand how the rules are structured, see `auto_report.py`. Each detection rule is little more than a function that returns a boolean True/False if certain strings are found in the various properties of the request object. There's probably a more efficient way to do this, but this works well enough for my use case; if I go much further here then I'd just be re-inventing the wheel that Fail2Ban and other tools already do far better.

# Deploying with Gunicorn+Nginx+Systemd, see deployment.md 

An example systemd service unit file is included, see `/etc/systemd/system/honeypot.service`. After configuring the service unit, place it in your systemd units directory (on Debian `/etc/systemd/system/`). Then you can run it as a systemd unit. Use `sudo systemctl enable honeypot.service && sudo systemctl start honeypot.service` to enable and start it. 

To-do: Deployment guide. Include Nginx proxy conf & systemd service unit. 

# Extra scripts for testing
`test-post-request.py` | Sends a POST request to localhost:5000 for testing. Accepts up to 2 parameters, which are used as the post data. For ex., to send `{'key1', 'value1'}` you would run `python test-send-request.py key1 value1`. If no parameters input then some default data is used. Can also do something like `./test-send-request.py $(head -c 32 /dev/urandom)` in a Bash shell.

`test-highvolume.py` | Send a bunch of GET + POST requests to localhost:5000, for testing/generating some records.

`test-post-bad-data.py` | POST some random data, not JSON-formatted.

`create-venv.sh` | Just creates a venv named `venv` in the current directory.

`deploy.sh` | This is NOT for production deployment, it only copies the main app files to another machine for development purposes - I use it to copy over new versions of the Flask blueprints to my "production" server where the app is already deployed, as an "update" script of sorts.

# Notes/issues:
- Will have to force Werkzeug=2.3.0 for a bit until flask-login release a version compatible with Werkzeug 3
- When refreshing stats page after toggling column views, checkboxes get out of sync - to fix, either force refresh (Ctrl+F5) or click the navbar link again. Need a better way of hiding columns.
- Querying for records by POST request body fails in some cases due to encoding discrepancies.

# To-do:
- Rewrite SQL queries, using SQLAlchemy instead of raw SQL.
- More specific detection rules/filters.
- Deployment guide - deployment.md - Include Nginx vhost conf file, systemd service unit example
- Filter stats by more data points. (condense into a dynamic Flask route for this like /stats/method/post)
- Filter out private IP ranges on stats pages? / Include config variable to not record requests from specific subnets.
- Configure a CIDR subnet from which to allow login.
