""" Main blueprint for stats pages, home, etc. Anything not related to auth can go in here. """

import sqlite3
#import requests
import json
import datetime
from socket import gethostbyaddr
from flask import request, render_template, jsonify, Response, send_from_directory, g, after_this_request, flash, Blueprint
from flask_login import login_required, current_user

main = Blueprint('main', __name__)

# Initialize bots database
# Should move this to models.py as a sqlAlchemy model, since I switched to blueprints.
def createDatabase(): # note: change column names to just match http headers, this schema is stupid and confusing.
    """ Create the bots.db database that will contain all the requests data. """
    conn = sqlite3.connect("bots.db")
    c = conn.cursor()
    c.execute("""
            CREATE TABLE IF NOT EXISTS bots(
            id INTEGER PRIMARY KEY,
            remoteaddr TEXT,
            hostname TEXT,
            useragent TEXT,
            requestmethod TEXT,
            querystring TEXT,
            time DATETIME,
            postjson TEXT,
            headers TEXT,
            url TEXT
            );
    """)
    conn.commit()
    c.close()
    conn.close()
    #print('Bots database initialized.')

    # Create Logins table
    conn = sqlite3.connect("bots.db")
    c = conn.cursor()
    c.execute("""
            CREATE TABLE IF NOT EXISTS logins(
            id INTEGER PRIMARY KEY,
            remoteaddr TEXT,
            username TEXT,
            password TEXT,
            time DATETIME
            );
    """)
    conn.commit()
    c.close()
    conn.close()
    #print('Logins database intialized.')

createDatabase()

@main.context_processor
def inject_title():
    '''Return the title to display on the navbar'''
    return {"SUBDOMAIN": 'lab.mepley', "TLD": '.com'}

# Define routes

@main.route('/', methods = ['POST', 'GET'], defaults = {'u_path': ''})
@main.route('/<path:u_path>', methods = ['POST', 'GET'])
def index(u_path):
    """ Catch-all route. Get and save all the request data into the database. """
    print(request) #for testing/ journalctl

    ## note: I *really* need to change these variable names to match the database/headers better

    if 'X-Real-Ip' in request.headers:#need to get real IP from behind Nginx proxy
        clientIP = request.headers.get('X-Real-Ip')
    else:
        clientIP = request.remote_addr
    # Get hostname by performing a DNS lookup
    try:
        clientHostname = gethostbyaddr(clientIP)[0]
    except:
        clientHostname = 'Unavailable'
    clientUserAgent = request.headers.get('User-Agent')
    reqMethod = request.method
    clientQuery = request.environ.get("QUERY_STRING")
    clientTime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    clientHeaders = dict(request.headers) # go ahead and save the full headers
    reqUrl = request.url

    # Get the POSTed data
    if reqMethod == 'POST':
        try:
            clientPostJson = request.json
            postData = json.dumps(clientPostJson)
        # If not valid JSON, that will fail, so try again as request.data
        except:
            try:
                badData = request.data
                postData = badData
            except Exception as e:
                postData = str(e) # So I can see if anything is still failing
    else:
        postData = '' #If not a POST request, use blank

    # do the sqlite stuff
    conn = sqlite3.connect("bots.db")
    c = conn.cursor()
    # c = g.db.cursor() # use g.db here if I use before_request to open the db connection
    sqlQuery = """INSERT INTO bots
        (id,remoteaddr,hostname,useragent,requestmethod,querystring,time,postjson,headers,url)
        VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?);"""
    dataTuple = (clientIP,
                clientHostname,
                clientUserAgent,
                reqMethod,
                clientQuery,
                clientTime,
                postData,
                str(clientHeaders),
                reqUrl)

    @after_this_request
    def closeConnection(response):
        """ Add response code to the tuple, commit and close db connection. """
        c.execute(sqlQuery, dataTuple)
        conn.commit()
        c.close()
        conn.close()
        #print(response.status) #For testing
        return response

    flash('IP: ' + clientIP, 'info')
    return render_template('index.html')

@main.route('/stats')
@login_required
def stats():
    """ Pull the most recent requests from bots.db and pass data to stats template to display. """
    conn = sqlite3.connect("bots.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    sqlQuery = "SELECT * FROM bots ORDER BY id DESC LIMIT 100;"
    c.execute(sqlQuery)
    stats = c.fetchall()
    totalHits = len(stats)

    # get total number of rows (= number of hits)
    sqlQuery = "SELECT COUNT(*) FROM bots"
    c.execute(sqlQuery)
    result = c.fetchone()
    totalHits = result[0]

    c.close()
    conn.close()

    return render_template('stats.html',
        stats = stats,
        totalHits = totalHits,
        statName = 'All HTTP Requests')

# To do: Change the stats routes to use a /stats/<statname> sort of scheme,
# with <statname> returning a certain view from database.
# Then make a new single stats template to display whatever data is returned.
# so i dont end up w a bunch of different pages to maintain.
# Using row factories it'll be easier to get column names when returning different views.

# Stats for the FAKE login
@main.route('/stats/logins')
@main.route('/loginstats')
@login_required
def loginStats():
    """ Query db for login attempts to the FAKE login route. """
    conn = sqlite3.connect('bots.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    # query most recent login attempts
    sqlQuery = "SELECT * FROM logins ORDER BY id DESC LIMIT 100;"
    c.execute(sqlQuery)
    loginAttempts = c.fetchall()
    # query for total # of rows
    sqlQuery = "SELECT COUNT(*) FROM logins"
    c.execute(sqlQuery)
    totalLogins = c.fetchone()[0]

    c.close()
    conn.close()

    #note: can just use flashed messages here, after I make a new stats template
    return render_template('loginstats.html',
        stats = loginAttempts,
        totalLogins = totalLogins)

@main.route('/ip/<ipAddr>', methods = ['GET'])
@login_required
def ipStats(ipAddr):
    """ Get stats of an individual IP. The IP column on main stats page will link to this route. """
    conn = sqlite3.connect('bots.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    sqlQuery = """
    SELECT * FROM bots WHERE remoteaddr = ? ORDER BY id DESC;
    """
    dataTuple = (ipAddr,)
    c.execute(sqlQuery, dataTuple)
    ipStats = c.fetchall()
    c.close()
    conn.close()

    return render_template('stats.html',
        stats = ipStats,
        totalHits = len(ipStats),
        statName = ipAddr)

@main.route('/stats/method/<method>', methods = ['GET'])
@login_required
def methodStats(method):
    """ Get stats by request method """
    #if method != 'GET' and method != 'POST':
    if method not in ('GET', 'POST'):
        flash('Bad request, must query for GET or POST. Try /method/GET or /method/POST', 'error')
        return render_template('index.html')
    conn = sqlite3.connect('bots.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    sqlQuery = """
    SELECT * FROM bots WHERE requestmethod = ? ORDER BY id DESC;
    """
    dataTuple = (method,)
    c.execute(sqlQuery, dataTuple)
    methodStats = c.fetchall()
    c.close()
    conn.close()

    return render_template('stats.html',
        stats = methodStats,
        totalHits = len(methodStats),
        statName = method
        )

@main.route('/profile')
@login_required
def profile():
    """Profile route just for testing login, can delete it later."""
    return render_template('profile.html', name=current_user.username)

@main.route('/about')
@login_required
def about():
    return render_template('about.html')

# Routes for security.txt + robots.txt
# Can also just serve them from Nginx
@main.route('/.well-known/security.txt')#Standard location
@main.route('/security.txt')
def securityTxt():
    """ Serve a security.txt in case Nginx isn't there to do it. """
    return send_from_directory('static', path='txt/security.txt')
@main.route('/robots.txt')
def robotsTxt():
    """ It's a honeypot, of course I want to allow bots. """
    return send_from_directory('static', path='txt/robots.txt')
