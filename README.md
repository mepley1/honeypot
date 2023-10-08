# Webpot
A simple honeypot for capturing and viewing HTTP GET/POST requests. Stores request data in a SQLite database for further analysis. 
Includes a catch-all route to catch both GET and POST requests for any URI. 
Very much a work in progress. 

[Live Demo](http://lab.mepley.com/) Note: May not be active at any given time. Demo login: user `demo` pw `0xDEADBEEF`

## To run locally:

Create and activate a venv:

`python3 -m venv venv`

`source venv/bin/activate`

Install required Python modules in the venv:

`pip install -r requirements.txt`

Edit the `SECRET_KEY` in `config.py` if you want cookies to work. 

Initialize database:

`python db_initialize.py`

Run the app:

`export FLASK_APP=project`

`export FLASK_DEBUG=true` - To turn on Flask debug mode if you want/need it

`flask run`

Then point your browser to http://localhost:5000 and log in

## Deploying with Gunicorn+Nginx+Systemd, see deployment.md 
To-do: Write guide. Include Nginx proxy conf & systemd service unit. 

# Features
- Catch-all route to catch requests to any URI
- Filter by IP/method
- Toggle display/hide data columns

## Extra scripts for testing
`send-request.py` | Sends a POST request to localhost:5000 for testing. Accepts up to 2 parameters, which are used as the post data. For ex., to send `{'key1', 'value1'}` you would run `./send-request.py key1 value1`. If no parameters input then some default data is used. Can also do something like `./send-request.py $(head -c 32 /dev/urandom)`

`test-highvolume.py` | Send a bunch of GET + POST requests to localhost:5000, for testing with higher volume. Creates a handful of threads. Change IP in script if not running on localhost. 

`create-venv.sh` | Creates a venv named `venv` in the current directory.

`deploy.sh` | This is NOT for production deployment, it only copies the main app files to another machine for development purposes - I use it to copy over new versions of the Flask blueprints to my "production" server where the app is already deployed. 

## Notes/issues:
- Will have to force Werkzeug=2.3.0 for a bit until flask-login release a version compatible with Werkzeug 3

## To-do:
- Deployment guide - deployment.md - Include wsgi.py, Nginx vhost conf file, systemd service unit example
- Edit templates to use semantic HTML tags wherever relevant, bots might read it better.
- Make script to report to AbuseIPDb: pull all records of the IP from the database/Nginx logs, and reports it. Include POSTed data/query string as comment if relevant. Maybe auto-report after a threshold, but auto-reporting is probably better left to fail2ban. 
- Add routes for common login pages + files that bots look for & catch credentials+data - XMLRPC, CMS txt files etc.
- Create a robots.txt, security.txt, etc to serve from Nginx
- Filter stats by more data points (condense into a dynamic Flask route for this like /stats/method/post, or stats/<variable>)
- Automatically check IPs via ipinfo.io API? This would use up a free plan quickly- check each IP only once. 
- Script to test high request volume, fuzz
- Filter out private IP spaces on stats pages?
- Script to create user acct
