from . import db
from flask import Flask, request, redirect, render_template, jsonify, Response, send_from_directory, g, after_this_request, flash, Blueprint
from flask_login import login_required, current_user
import random
import string
import sqlite3
import html
import requests
import json
import datetime
import secrets
from socket import gethostbyaddr


main = Blueprint('main', __name__)

@main.context_processor
def inject_title():
    return dict(SUBDOMAIN="lab.mepley", TLD=".com")

# Initialize bots database
# Should move this to __init__.py and use sqlAlchemy to do it
def createDatabase(): # note: change column names to just match http headers, this schema is stupid and confusing.
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
    print('Bots database initialized.')

    # create Logins table
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
    print('Logins database intialized.')

createDatabase()

# Define routes

@main.route('/', methods = ['POST', 'GET'], defaults = {'u_path': ''})
@main.route('/<path:u_path>', methods = ['POST', 'GET'])
def index(u_path):
    print(request) #for testing

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
    
    if reqMethod == 'POST':
        try:
            #clientPostData = request.get_json() # Only if you know it will be JSON
            #clientPostData = request.data
            clientPostJson = request.json
            jsonData = json.dumps(clientPostJson)
        except Exception as e:
            jsonData = str(e) # So I can see what caused the failure

        #if b'..' in clientPostData:
        #    return jsonify({'error': "Dont do that."}), 400 # prevent directory traversal depending on what method I use to get the POST data
    else:
        #clientPostData = ''
        jsonData = ''
    
    # do the sqlite stuff
    conn = sqlite3.connect("bots.db")
    c = conn.cursor()
    # c = g.db.cursor() # use g.db here if I use before_request to open the db connection
    sqlQuery = """INSERT INTO bots 
        (id,remoteaddr,hostname,useragent,requestmethod,querystring,time,postjson,headers,url)
        VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?);"""
    dataTuple = (clientIP, clientHostname, clientUserAgent, reqMethod, clientQuery, clientTime, jsonData, str(clientHeaders), reqUrl)


    #print('Received a hit: Wrote to database successfully.')
    #print(request) #testing

    # add the response code to the tuple, then commit, then close connection
    @after_this_request
    def closeConnection(response):
        #print('After_this_request now executing') # for testing
        c.execute(sqlQuery, dataTuple)
        conn.commit()
        c.close()
        conn.close()
        return response

    flash('IP: ' + clientIP, 'info')
    return render_template('index.html')

# Profile route just for testing login, can delete it later
@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name=current_user.username)

@main.route('/about')
def about():
    return render_template('about.html')

@main.route('/stats')
@login_required
def stats():
    # pull the most recent 100 requests from bots.db and pass the data to stats.html template to display
    conn = sqlite3.connect("bots.db")
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    sqlQuery = "SELECT * FROM bots ORDER BY id DESC LIMIT 100;"
    c.execute(sqlQuery)
    stats = c.fetchall()
    totalHits = len(stats)
    c.close()
    conn.close()

    # get total number of rows (= number of hits)
    # note: don't really need to make 2 separate connections, I'll consolidate queries later
    conn = sqlite3.connect("bots.db")
    c = conn.cursor()
    sqlQuery = "SELECT COUNT(*) FROM bots"
    c.execute(sqlQuery)
    result = c.fetchone()
    totalHits = result[0]
    c.close()
    conn.close()

    return render_template('stats.html', stats = stats, totalHits = totalHits, statName = 'All HTTP Requests')


# To do: Change the stats routes to use a /stats/<statname> sort of scheme, with <statname> returning a certain view from database
# then make a new single stats template to display whatever data is returned.
# so i dont end up w a bunch of different pages to maintain.
# Using row factories it'll be easier to get column names when returning different views.

# Stats for the FAKE login
@main.route('/stats/logins') 
@main.route('/loginstats')
@login_required
def loginStats():
    conn = sqlite3.connect('bots.db')
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    # query most recent login attempts
    sqlQuery = "SELECT * FROM logins ORDER BY id DESC LIMIT 100;"
    c.execute(sqlQuery)
    loginStats = c.fetchall()
    # query for total # of rows
    sqlQuery = "SELECT COUNT(*) FROM logins"
    c.execute(sqlQuery)
    totalLogins = c.fetchone()[0]
    
    c.close()
    conn.close()

    return render_template('loginstats.html', stats = loginStats, totalLogins = totalLogins) #note: can just use flashed messages here, after I make a new stats template

# This route will return stats of an individual IP.
# The main stats page will link to this route.
@main.route('/ip/<ipAddr>', methods = ['GET'])
@login_required
def ipStats(ipAddr):
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

    return render_template('stats.html', stats = ipStats, totalHits = len(ipStats), statName = ipAddr)

# Return all rows where request method = GET/POST
@main.route('/stats/method/<method>', methods = ['GET'])
@login_required
def methodStats(method):
    if method != 'GET' and method != 'POST':
        #return 'Bad request, method must be GET or POST', 400
        flash('Bad request, method must be GET or POST. Try /stats/method/GET or /stats/method/POST', 'error')
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

    return render_template('stats.html', stats = methodStats, totalHits = len(methodStats), statName = method)


# The FAKE(honeypot) login route
# The real one is in auth.py (@auth.login)
# Going to change this since I have real auth now, but leaving it here for now.
@main.route('/nigol')
def nigol():
    # do stuff
    return render_template('index.html')

# Routes for security.txt + robots.txt
# Can also just serve them from Nginx
@main.route('/.well-known/security.txt')
@main.route('/security.txt')
def securityTxt():
    return send_from_directory('static', path='txt/security.txt')
@main.route('/robots.txt')
def robotsTxt():
    return send_from_directory('static', path='txt/robots.txt')
