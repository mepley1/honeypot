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
    # Need to get real IP from behind Nginx proxy
    if 'X-Real-Ip' in request.headers:
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
        except:
            # If not valid JSON, fall back to request.data
            try:
                saved_data = request.get_data() #If calling get_data() AFTER request.data, it'll return empty bytes obj, so save it first
                bad_data = request.data.decode('utf-8')
                posted_data = bad_data
                if not posted_data:
                    #If request.data can't parse it and returns an empty object
                    posted_data = saved_data
                    logging.debug('Couldnt parse data, falling back to request.get_data')
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
    records_limit = request.args.get('limit') or '100' # Limit to certain # of records

    if records_limit.isnumeric():
        records_limit = int(records_limit)
    else:
        flash('Bad request. Limit must be a positive integer.', 'error')
        return render_template('index.html')

    with sqlite3.connect("bots.db") as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Grab most recent hits.
        sqlQuery = "SELECT * FROM bots ORDER BY id DESC LIMIT ?;"
        data_tuple = (records_limit,)
        c.execute(sqlQuery, data_tuple)
        stats = c.fetchall()

        # get total number of rows (= number of hits)
        sqlQuery = "SELECT COUNT(*) FROM bots"
        c.execute(sqlQuery)
        result = c.fetchone()
        totalHits = result[0]

        # Get most common IP. Break ties in favor of most recent.
        sqlQuery = """
            SELECT remoteaddr, COUNT(*) AS count
            FROM bots
            GROUP BY remoteaddr
            ORDER BY count DESC, MAX(id) DESC
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
        statName = f'Most Recent {records_limit} HTTP Requests',
        top_ip = top_ip
        )

# To do: Change the stats routes to use a single /stats/<statname> sort of scheme,
# with <statname> returning a certain view from database.
# Then make a new single stats template to display whatever data is returned,
# so i dont end up w a bunch of different pages+routes to maintain.
# Using row factories it'll be easier to get column names when returning different views.

# Login attempt stats
@main.route('/stats/logins')
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
            SELECT * FROM bots WHERE (postjson LIKE ?) ORDER BY id DESC;
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

@main.route('/stats/reported', methods = ['GET'])
@login_required
def reported_stats():
    """ Get records of requests that were reported. """
    reported_status = request.args.get('reported')
    # Flash an error message if querying for a method not in db
    if reported_status not in ('0', '1'):
        flash('Bad request. Try reported=0 or reported=1', 'error')
        return render_template('index.html')

    with sqlite3.connect('bots.db') as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for reported 0/1
        sql_query = """
            SELECT * FROM bots
            WHERE reported = ?
            ORDER BY id DESC;
            """
        data_tuple = (reported_status,)
        c.execute(sql_query, data_tuple)
        reported_stats = c.fetchall()

        # Get total number of reports, most reported IP
        sql_query = """
            SELECT remoteaddr, COUNT(*) AS count
            FROM bots
            WHERE reported = ?
            GROUP BY remoteaddr
            ORDER BY count DESC, MAX(id) DESC
            LIMIT 1;
            """
        c.execute(sql_query, data_tuple)
        top_reported = c.fetchone()
        top_reported_ip_count = top_reported['count']
        top_reported_ip_addr = top_reported['remoteaddr']

        c.close()
    conn.close()

    # Flash a message based on reported or unreported
    if reported_status == '1':
        message_a = f'Most reported IP: {top_reported_ip_addr}, reported {top_reported_ip_count} times.'
    elif reported_status == '0':
        message_a = f'Most unreported IP: {top_reported_ip_addr}, slipped by {top_reported_ip_count} times.'

    flash(message_a, 'info')
    return render_template('stats.html',
        stats = reported_stats,
        totalHits = len(reported_stats),
        statName = f'Reported (1=True, 0=False): {reported_status}',
        #top_ip = top_reported
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
