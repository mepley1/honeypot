""" Main blueprint for stats pages, home, etc. Anything not related to auth can go in here. """

import sqlite3
import requests #for reporting
import json
import datetime
import logging
from .auto_report import check_all_rules #The new report module. Will check rules + report
from socket import gethostbyaddr
from flask import request, render_template, jsonify, Response, send_from_directory, g, after_this_request, flash, Blueprint, current_app
from flask_login import login_required, current_user
from urllib.parse import unquote # for uaStats()

main = Blueprint('main', __name__)

# Initialize bots database
# Should move this to models.py as a sqlAlchemy model, since I switched to blueprints.
def createDatabase(): # note: change column names to just match http headers, this schema is stupid and confusing.
    """ Create the bots.db database that will contain all the requests data. """
    with sqlite3.connect("bots.db") as conn:
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
                url TEXT,
                reported NUMERIC
                );
        """)
        #logging.debug('Bots table initialized.')

        # Create Logins table
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
    #logging.debug('Logins table intialized.')

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
    logging.info(request)

    ## note: I *really* need to change these variable names to match the database/headers better

    if 'X-Real-Ip' in request.headers:#need to get real IP from behind Nginx proxy
        clientIP = request.headers.get('X-Real-Ip')
    else:
        clientIP = request.remote_addr
    
    try: # Get hostname by performing a DNS lookup
        clientHostname = gethostbyaddr(clientIP)[0]
    except:
        clientHostname = 'Unavailable'
    clientUserAgent = request.headers.get('User-Agent')
    reqMethod = request.method
    clientQuery = request.query_string.decode()
    clientTime = datetime.datetime.now().astimezone().replace(microsecond=0).isoformat() #Compatible with ApuseIPDB API
    clientHeaders = dict(request.headers) # go ahead and save the full headers
    if 'Cookie' in clientHeaders:
        clientHeaders['Cookie'] = '[REDACTED]' # Don't expose session cookies!
    reqUrl = request.url

    # Get the POSTed data
    if reqMethod == 'POST':
        try:
            posted_json = request.json
            posted_data = json.dumps(posted_json)
        # If not valid JSON, that will fail, so try again as request.data in case it's XML etc
        except:
            try:
                #bad_data = request.data
                bad_data = request.get_data() #get_data will save it as is
                posted_data = bad_data
            except Exception as e:
                posted_data = str(e) # So I can see if anything is still failing
    else:
        posted_data = '' #If not a POST request, use blank

    reported = check_all_rules() #see auto_report.py

    sqlQuery = """INSERT INTO bots
        (id,remoteaddr,hostname,useragent,requestmethod,querystring,time,postjson,headers,url,reported)
        VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"""
    dataTuple = (clientIP,
                clientHostname,
                clientUserAgent,
                reqMethod,
                clientQuery,
                clientTime,
                posted_data,
                str(clientHeaders),
                reqUrl,
                reported)

    @after_this_request
    def closeConnection(response):
        """ Add response code to the tuple, commit and close db connection. """
        with sqlite3.connect('bots.db') as conn:
            c = conn.cursor()
            c.execute(sqlQuery, dataTuple)
            conn.commit()
        conn.close()

        #logging.debug(response.status) #For testing
        return response

    flash(f'IP: {clientIP}', 'info')
    return render_template('index.html')

@main.route('/stats')
@login_required
def stats():
    """ Pull the most recent requests from bots.db and pass data to stats template to display. """
    with sqlite3.connect("bots.db") as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Grab most recent hits.
        sqlQuery = "SELECT * FROM bots ORDER BY id DESC LIMIT 100;"
        c.execute(sqlQuery)
        stats = c.fetchall()

        # get total number of rows (= number of hits)
        sqlQuery = "SELECT COUNT(*) FROM bots"
        c.execute(sqlQuery)
        result = c.fetchone()
        totalHits = result[0]

        # Get most common IP
        '''
        sqlQuery = """
            SELECT remoteaddr, COUNT(*) AS count
            FROM bots
            GROUP BY remoteaddr
            ORDER BY count DESC
            LIMIT 1;
            """
        '''

        #Get most common IP; break tie in favor of most recent
        sqlQuery = """
        SELECT remoteaddr, COUNT(*) AS count
        FROM bots
        GROUP BY remoteaddr
        HAVING count = (
            SELECT MAX(count)
            FROM (
                SELECT COUNT(*) AS count
                FROM bots
                GROUP BY remoteaddr
            )
        )
        ORDER BY (
            SELECT MAX(time)
            FROM bots AS b
            WHERE b.remoteaddr = bots.remoteaddr
        ), count DESC
        LIMIT 1;
        """

        c.execute(sqlQuery)
        top_ip = c.fetchone()
        if top_ip:
            top_ip_addr = top_ip['remoteaddr']
            top_ip_count = top_ip['count']

        c.close()
    conn.close()

    return render_template('stats.html',
        stats = stats,
        totalHits = totalHits,
        statName = 'Most Recent HTTP Requests',
        top_ip = top_ip
        )

# To do: Change the stats routes to use a single /stats/<statname> sort of scheme,
# with <statname> returning a certain view from database.
# Then make a new single stats template to display whatever data is returned,
# so i dont end up w a bunch of different pages+routes to maintain.
# Using row factories it'll be easier to get column names when returning different views.

# Login attempt stats
@main.route('/stats/logins')
@main.route('/loginstats')
@login_required
def loginStats():
    """ Query db for login attempts. """
    with sqlite3.connect('bots.db') as conn:
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
    """ Get records of an individual IP. The IP column on stats page will link to this route. """
    with sqlite3.connect('bots.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        sqlQuery = "SELECT * FROM bots WHERE remoteaddr = ? ORDER BY id DESC;"
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
    """ Get records by request method """
    # Flash an error message if querying for a method not in db
    if method not in ('GET', 'POST', 'HEAD'):
        flash('Bad request. Try /method/GET or /method/POST', 'error')
        return render_template('index.html')

    with sqlite3.connect('bots.db') as conn:
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

@main.route('/stats/useragent', methods = ['GET'])
@login_required
def uaStats():
    """ Get stats matching the user agent string. """
    ua = unquote(request.args.get('ua', '')) #The link on stats page encodes it

    with sqlite3.connect('bots.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching user agent
        sqlQuery = """
            SELECT * FROM bots WHERE useragent = ? ORDER BY id DESC;
            """
        dataTuple = (ua,)
        c.execute(sqlQuery, dataTuple)
        uaStats = c.fetchall()
        c.close()
    conn.close()

    return render_template('stats.html',
        stats = uaStats,
        totalHits = len(uaStats),
        statName = f"User-Agent: {ua}"
        )

@main.route('/stats/url', methods = ['GET'])
@login_required
def urlStats():
    """ Get stats matching the URL. """
    url = request.args.get('url', '')

    with sqlite3.connect('bots.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching user agent
        sqlQuery = """
            SELECT * FROM bots WHERE url = ? ORDER BY id DESC;
            """
        dataTuple = (url,)
        c.execute(sqlQuery, dataTuple)
        urlStats = c.fetchall()
        c.close()
    conn.close()

    return render_template('stats.html',
        stats = urlStats,
        totalHits = len(urlStats),
        statName = f"URL: {url}"
        )

@main.route('/stats/query', methods = ['GET'])
@login_required
def queriesStats():
    """ Get records matching the Query String. """
    query_params = request.args.get('query', '')

    with sqlite3.connect('bots.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching user agent
        sqlQuery = """
            SELECT * FROM bots WHERE querystring = ? ORDER BY id DESC;
            """
        dataTuple = (query_params,)
        c.execute(sqlQuery, dataTuple)
        queriesStats = c.fetchall()
        c.close()
    conn.close()

    return render_template('stats.html',
        stats = queriesStats,
        totalHits = len(queriesStats),
        statName = f"Query String: {query_params}"
        )

@main.route('/stats/body', methods = ['GET'])
@login_required
def bodyStats():
    """ Get records matching the POST request body. """
    body = request.args.get('body')

    with sqlite3.connect('bots.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching request body
        sqlQuery = """
            SELECT * FROM bots WHERE postjson = ? ORDER BY id DESC;
            """
        dataTuple = (body,)
        c.execute(sqlQuery, dataTuple)
        bodyStats = c.fetchall()
        c.close()
    conn.close()

    return render_template('stats.html',
        stats = bodyStats,
        totalHits = len(bodyStats),
        statName = f"Request Body: {body}"
        )

# Misc routes

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
