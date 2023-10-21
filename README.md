# Webpot
A simple honeypot for capturing and viewing HTTP GET/POST requests + auto reporting. Stores request data in a SQLite database for further analysis. 
Includes a catch-all route to catch both GET and POST requests for any URI. 
Very much a work in progress. 

[Live Demo](http://lab.mepley.com/) Note: May not be active or up to date at any given time. Demo login: user `demo` pw `0xDEADBEEF`

## To run locally:

Create and activate a venv:

`python3 -m venv venv`

`source venv/bin/activate`

Install required Python modules in the venv:

`pip install -r requirements.txt`

Configuration (Set either in config.py or as environment variables):
1. Edit the `SECRET_KEY` in `config.py` if you want cookies to work, or export it as an environment variable: `export FLASK_SECRET_KEY=0123456789`
2. `export FLASK_ABUSEIPDB=0123456789` - Set your AbuseIPDB API key, for auto-reporting.
3. `export FLASK_DEBUG=true` - To turn on Flask debug mode if you want/need it for development.

Initialize database:

`python db_initialize.py`

Create a login:

`python create-user.py <username>`

Run the app:

`export FLASK_APP=project`

`flask run`

Then point your browser to http://localhost:5000 and log in

# Features
- Catch-all route to catch requests for any URI
- Stats views to filter by IP/method/UA/URL/query/body
- Toggle display/hide data columns
- Now has proper auth + remember me (must set `SECRET_KEY` in `config.py`/ env vars.)
- Limited auto reporting. (must set `ABUSEIPDB` in config = AbuseIPDB API key)

# Deploying with Gunicorn+Nginx+Systemd, see deployment.md 

An example systemd service unit file is included, see `/etc/systemd/system/honeypot.service`. After configuring the service unit, place it in your systemd units directory (on Debian `/etc/systemd/system/`). Then you can run it as a systemd unit. Use `sudo systemctl enable honeypot.service && sudo systemctl start honeypot.service` to enable and start it. 

To-do: Deployment guide. Include Nginx proxy conf & systemd service unit. 

# Extra scripts for testing
`test-send-request.py` | Sends a POST request to localhost:5000 for testing. Accepts up to 2 parameters, which are used as the post data. For ex., to send `{'key1', 'value1'}` you would run `python test-send-request.py key1 value1`. If no parameters input then some default data is used. Can also do something like `./test-send-request.py $(head -c 32 /dev/urandom)` in a Bash shell.

`test-highvolume.py` | Send a bunch of GET + POST requests to localhost:5000, for testing with slightly higher volume. Change IP in script if not running on localhost. 

`test-post-bad-data.py` | POST some random data, not JSON-formatted.

`create-venv.sh` | Just creates a venv named `venv` in the current directory.

`deploy.sh` | This is NOT for production deployment, it only copies the main app files to another machine for development purposes - I use it to copy over new versions of the Flask blueprints to my "production" server where the app is already deployed. 

# Notes/issues:
- Will have to force Werkzeug=2.3.0 for a bit until flask-login release a version compatible with Werkzeug 3
- When refreshing stats page after toggling column views, checkboxes get out of sync - to fix, either force refresh (Ctrl+F5) or click the navbar link again. Need a better way of hiding columns.
- Querying for records by POST request body fails in some cases due to encoding discrepancies.

# To-do:
- More rules/filters for auto-reporting - still deciding how I want to handle rules.
- Deployment guide - deployment.md - Include Nginx vhost conf file, systemd service unit example
- Filter stats by more data points. (condense into a dynamic Flask route for this like /stats/method/post)
- Automatically check IPs via ipinfo API? This would use up a free plan quickly- check each IP only once every so often. 
- Scripts to test high request volume, + fuzz
- Filter out private IP ranges on stats pages? / Include config variable to not record requests from specific CIDR subnets.
