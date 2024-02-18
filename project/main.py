""" Main blueprint for stats pages, home, etc. Anything not related to auth can go in here. """

import ast
import sqlite3
import requests #for reporting
import json
import datetime
import logging
import ipaddress
import re
from .auto_report import check_all_rules, get_real_ip #The new report module. Will check rules + report
from socket import gethostbyaddr, herror
from flask import request, redirect, url_for, render_template, jsonify, Response, send_from_directory, g, after_this_request, flash, Blueprint, current_app
from flask_login import login_required, current_user
from urllib.parse import unquote # for uaStats()
from functools import wraps

main = Blueprint('main', __name__)
requests_db = 'bots.db'

# Initialize bots database
# Should move this to models.py as a sqlAlchemy model.
def createDatabase(): # note: change column names to just match http headers, this schema is stupid and confusing.
    """ Create the bots.db database that will contain all the requests data. """
    with sqlite3.connect(requests_db) as conn:
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
                reported NUMERIC,
                contenttype TEXT,
                country TEXT
                );
        """)
        #logging.debug('Bots table initialized.')

        # Create Logins table, to record login attempts.
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

# note: Use a Flask config variable for this, right now it's duplicated across blueprints
@main.context_processor
def inject_title():
    '''Return the title to display on the navbar'''
    title_subdomain = current_app.config.get('SITE_TITLE_SUBDOMAIN', 'lab.mepley')
    title_tld = current_app.config.get('SITE_TITLE_TLD', '.com')
    return {"SUBDOMAIN": title_subdomain, "TLD": title_tld}

# decorator to require admin user
def admin_required(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            logging.info(f'Attempted unauthorized action by user {current_user.username}')
            flash('Not authorized: User must have admin privilege.', 'errorn')
            try:
                return redirect(request.referrer)
            except:
                return redirect(url_for('main.index'))
        return func(*args, **kwargs)
    return decorated_function

# Validate an IP address
def validate_ip_query(_ip):
    """ Validate queried IP. """
    # IPv4/v6 chars + GLOB chars. Loose max length to account for glob queries, otherwise 39.
    ip_pattern = r'^[0-9A-Fa-f.:*\[\]\-^]{1,60}$'
    regex = re.compile(ip_pattern)
    if regex.match(_ip):
        return True
    else:
        return False

def validate_id_query(_id):
    """ Validate queried ID #. """
    # Numbers + GLOB chars. Loose max length to account for glob queries.
    id_pattern = r'^[0-9*\[\]\-^?]{1,24}$'
    regex = re.compile(id_pattern)
    if regex.match(_id):
        return True
    else:
        return False

# Define routes

# Will use this in a couple places so I don't have to list them all out
HTTP_METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH']

@main.route('/', methods = HTTP_METHODS, defaults = {'u_path': ''})
@main.route('/<path:u_path>', methods = HTTP_METHODS)
def index(u_path):
    """ Catch-all route. Get and save all the request data into the database. """
    logging.info(f'{request}')

    ## note: I *really* need to change these variable names to match the database/headers better
    
    # Need to get real IP from behind Nginx reverse proxy
    req_ip = get_real_ip()
    req_url = request.url

    try: # Get hostname by performing a DNS lookup
        req_hostname = gethostbyaddr(req_ip)[0]
    except herror as e:
        req_hostname = 'Unavailable'
        logging.debug(f'No hostname available, or no connection: {str(e)}')

    req_user_agent = request.headers.get('User-Agent', '')
    req_method = request.method
    req_query = request.query_string.decode()
    #Timestamp compatible with ApuseIPDB API
    req_time = datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()
    req_headers = dict(request.headers) # go ahead and save the full headers
    if 'Cookie' in req_headers:
        req_headers['Cookie'] = '[REDACTED]' # Don't expose session cookies! Will be displayed later.
    #Note: Add the following to the database schema later
    req_from_contact = request.headers.get('From')
    req_country_code = request.headers.get('Cf-Ipcountry', '')

    # NEW SECTION: Get the POST request body
    # Get the request body. Could be any content-type, format, encoding, etc, try to capture
    # and decode as much as possible. Don't rely on declared encodings etc because some wild attacks
    # that I want to capture may involve exploiting discrepancies.
    # Not checking for POST method, as occasionally GET requests have a body as well.
    ## Decoding notes: According to https://stackoverflow.com/questions/74276512/can-you-safely-read-utf8-and-latin1-files-with-a-na%C3%AFve-try-except-block
    ### A comment says: "Your initial assumption is right: if a file that can only be utf-8 of latin1 encoded cannot be read as utf-8, then it is latin1 encoded.
    ### The fact is that any sequence of bytes can be decoded as latin1 because there the latin1 encoding is a bijection between the 256 possible bytes and the unicode characters with code point in the [0;256[ range.
    # So for now I *think* my tactic of trying decode as utf-8 and then latin-1 second is right, and should produce minimal mojibake, unless the data is neither utf-8 nor latin-1.

    #req_content_type = request.content_type #This returns a None if no content-type declared, so use headers.get() with a default instead
    req_content_type = request.headers.get('Content-Type', '')

    try:
        # JSON: Serialize the body data, if that doesn't work just use get_data().
        if 'application/json' in req_content_type:
            try:
                #req_body = json.dumps(request.json)
                req_body = json.dumps(request.get_json(force=True))
            except:
                logging.debug('Serializing failed, attempting to decode as utf-8...')
                req_body = request.get_data().decode('utf-8', errors = 'backslashreplace')
        elif 'application/x-www-form-urlencoded' in req_content_type:
            # If content-type is Form data. 
            if isinstance(request.get_data(), bytes):
                """If body is bytes: try utf-8 first, if that doesn't work then latin-1.
                Should add a database column later for un-decoded body, as well as which set worked. """
                try:
                    logging.debug('Form data is bytes. Attempting to parse as utf-8...')
                    req_body = request.get_data().decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        logging.debug('Attempting to parse as latin-1...')
                        req_body = request.get_data().decode('latin-1')
                    except UnicodeDecodeError:
                        logging.debug('Fuck it, just use replacement chars if utf-8 or latin-1 dont work.')
                        req_body = request.get_data().decode('utf-8', errors = 'backslashreplace')
            else:
                """ If not bytes, either serialize it if possible, or decode. """
                try:
                    req_body = json.dumps(dict(request.form)) #This is resulting in an empty string if it can't parse it
                except TypeError as e:
                    logging.debug('Form data not serializable, trying get_data()...')
                    req_body = request.get_data().decode('utf-8', errors = 'replace')
        if 'text/html' in req_content_type or 'text/plain' in req_content_type:
            req_body = request.get_data().decode('utf-8', errors = 'backslashreplace')
        else: #Any other content-type, or if no content-type declared
            try:
                req_body = request.get_data().decode('utf-8')
            except UnicodeDecodeError:
                req_body = request.get_data().decode('utf-8', errors = 'backslashreplace')
    except Exception as e:
        #If any other exceptions
        logging.error(f'Exception while trying to parse body. Saving with backslashreplace. : {str(e)}')
        #req_body = str(e) #See if anything is still failing
        req_body = request.get_data().decode('utf-8', errors='backslashreplace')
        #req_body = request.data


    # Check request against detection rules, and submit report
    # Adding try/except temporarily while I test some things
    try:
        reported = check_all_rules() #see auto_report.py
    except Exception as e:
        logging.error(f'Error while executing detections: {str(e)}')
        reported = 0

    # Request data to insert into the database
    sql_query = """INSERT INTO bots
        (id,remoteaddr,hostname,useragent,requestmethod,querystring,time,postjson,headers,url,reported,contenttype,country)
        VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"""
    data_tuple = (req_ip,
                req_hostname,
                req_user_agent,
                req_method,
                req_query,
                req_time,
                req_body,
                str(req_headers),
                req_url,
                reported,
                req_content_type,
                req_country_code)

    @after_this_request
    def closeConnection(response):
        """ Add response code to the tuple, commit and close db connection. """
        with sqlite3.connect(requests_db) as conn:
            c = conn.cursor()
            c.execute(sql_query, data_tuple)
            conn.commit()
        conn.close()

        #logging.debug(response.status) #For testing
        return response

    flash(f'IP: {req_ip}', 'info')
    return render_template('index.html')

@main.route('/stats')
@login_required
def stats():
    """ Pull the most recent requests from bots.db and pass data to stats template to display. """
    records_limit = request.args.get('limit') or '100' # Limit to certain # of records, default 100

    if records_limit.isnumeric():
        records_limit = int(records_limit)
    else:
        flash('Bad request: `limit` must be a positive integer.', 'error')
        return render_template('index.html')

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # Grab most recent hits.
        sql_query = "SELECT * FROM bots ORDER BY id DESC LIMIT ?;"
        data_tuple = (records_limit,)
        c.execute(sql_query, data_tuple)
        stats = c.fetchall()

        # get total number of rows (= number of hits)
        sql_query = "SELECT COUNT(*) FROM bots"
        c.execute(sql_query)
        result = c.fetchone()
        totalHits = result[0]

        # Get most common IP. Break ties in favor of most recent.
        sql_query = """
            SELECT remoteaddr, COUNT(*) AS count
            FROM bots
            GROUP BY remoteaddr
            ORDER BY count DESC, MAX(id) DESC
            LIMIT 1;
        """
        c.execute(sql_query)
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
@admin_required
def loginStats():
    """ Query db for login attempts. """
    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()

        # query most recent login attempts
        sql_query = "SELECT * FROM logins ORDER BY id DESC LIMIT 100;"
        c.execute(sql_query)
        login_attempts = c.fetchall()

        # query for total # of rows
        sql_query = "SELECT COUNT(*) FROM logins"
        c.execute(sql_query)
        total_logins = c.fetchone()[0]

        c.close()
    conn.close()

    #note: can just use flashed messages here, after I make a new stats template
    return render_template('loginstats.html',
        stats = login_attempts,
        totalLogins = total_logins)

@main.route('/stats/ip/<ipAddr>', methods = ['GET'])
@login_required
def ipStats(ipAddr):
    """ Get records of an individual IP. The IP column on stats page will link to this route. """
    # Validate the given IP first:
    if not validate_ip_query(ipAddr):
        flash('Bad request: Contains invalid characters.', 'errorn')
        return render_template('index.html')

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Using GLOB instead of = to allow checking for a subnet more easily, i.e. 123.45.67.*
        sql_query = "SELECT * FROM bots WHERE (remoteaddr GLOB ?) ORDER BY id DESC;"
        data_tuple = (ipAddr,)
        c.execute(sql_query, data_tuple)
        ipStats = c.fetchall()

        c.close()
    conn.close()

    flash('Note: Use * in URL for wildcard, i.e. /stats/ip/1.2.3.*', 'info')
    return render_template('stats.html',
        stats = ipStats,
        totalHits = len(ipStats),
        statName = ipAddr)

@main.route('/stats/ip/topten', methods = ['GET'])
@login_required
def top_ten_ips():
    """ Return top ten most common IPs. """
    _num_of_ips = request.args.get('limit', 10) # num of IPs to include, i.e. Top X IPs. default 10
    if not isinstance(_num_of_ips, int):
        flash('Bad request: `limit` must be type int', 'error')
        return render_template('index.html')

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT remoteaddr, COUNT(*) AS count FROM bots GROUP BY remoteaddr ORDER BY count DESC LIMIT ?;"
        # Execute the SQL query to get the 10 most common remoteaddr values
        data_tuple = (_num_of_ips,)
        c.execute(sql_query, data_tuple)
        top_ips = c.fetchall()

        # Now query for all requests received from top_ips
        top_ips_addrs = [row['remoteaddr'] for row in top_ips]
        logging.debug(f'Top IPs: {top_ips_addrs}') #testing, delete this
        top_ips_str = ', '.join(top_ips_addrs)

        logging.debug(','.join(top_ips_addrs*len(top_ips_addrs))) #testing, delete

        #sql_query = "SELECT * FROM bots WHERE remoteaddr IN ( ? ) ORDER BY id DESC LIMIT 100;"
        sql_query = f"SELECT * FROM bots WHERE remoteaddr IN ({ ','.join(['?']*len(top_ips_addrs)) }) ORDER BY id DESC;"
        data_tuple_b = (top_ips_str,)

        c.execute(sql_query, top_ips_addrs)
        results = c.fetchall()

        c.close()
    conn.close()

    # Print the results
    for row in top_ips:
        flash(f'IP: {row["remoteaddr"]}, Count: {row["count"]}', 'info')
    return render_template('stats.html',
        stats = results,
        totalHits = len(results),
        statName = f'Top {_num_of_ips} most common IPs'
        )

@main.route('/stats/method/<method>', methods = ['GET'])
@login_required
def methodStats(method):
    """ Get records by request method """
    # Flash an error message if querying for a method not in db
    if method not in HTTP_METHODS:
        flash('Bad request. Must query for a valid HTTP method, try /method/GET or /method/POST, etc.', 'error')
        return render_template('index.html')

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = """
            SELECT * FROM bots WHERE requestmethod = ? ORDER BY id DESC;
            """
        data_tuple = (method,)
        c.execute(sql_query, data_tuple)
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

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching user agent
        sql_query = """
            SELECT * FROM bots WHERE (useragent LIKE ?) ORDER BY id DESC;
        """
        data_tuple = (ua,)
        c.execute(sql_query, data_tuple)
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

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching URL
        sql_query = """
            SELECT * FROM bots WHERE (url GLOB ?) ORDER BY id DESC;
            """
        data_tuple = (url,)
        c.execute(sql_query, data_tuple)
        urlStats = c.fetchall()
        c.close()
    conn.close()

    flash('Use * in URL for wildcard, i.e. /stats/url?url=*.example.com/*', 'info')
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

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching user agent
        sql_query = """
            SELECT * FROM bots WHERE (querystring LIKE ?) ORDER BY id DESC;
            """
        data_tuple = (query_params,)
        c.execute(sql_query, data_tuple)
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
    body = request.args.get('body', '')

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching request body
        sql_query = """
            SELECT * FROM bots WHERE (postjson LIKE ?) ORDER BY id DESC;
            """
        data_tuple = (body,)
        c.execute(sql_query, data_tuple)
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
    reported_status = request.args.get('reported', '1')
    # Validate
    if reported_status not in ('0', '1'):
        flash('Bad request. Try reported=0 or reported=1', 'error')
        return render_template('index.html')

    with sqlite3.connect(requests_db) as conn:
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
        top_reported_ip_message = f'Most reported IP: {top_reported_ip_addr}, reported {top_reported_ip_count} times.'
    elif reported_status == '0':
        top_reported_ip_message = f'Most un-reported IP: {top_reported_ip_addr}, slipped by {top_reported_ip_count} times.'

    flash(top_reported_ip_message, 'info')
    return render_template('stats.html',
        stats = reported_stats,
        totalHits = len(reported_stats),
        statName = f'Reported (1=True, 0=False): {reported_status}',
        #top_ip = top_reported
        )

# query for Proxy-Connection header
@main.route('/stats/headers/proxy-connection', methods = ['GET'])
@login_required
def proxy_connection_header_stats():
    """ Get records containing a Proxy-Connection header. (i.e. attempts to proxy the request to another host).
    Can also query for ?header_string=%25proxy%25 to check for anything with the word 'proxy'. """
    header_string = request.args.get('header_string', "%'proxy-%")

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for Proxy-Connection header.
        sql_query = """
            SELECT * FROM bots WHERE (headers LIKE ?) ORDER BY id DESC;
            """
        data_tuple = (header_string,)
        c.execute(sql_query, data_tuple)
        proxy_connection_stats = c.fetchall()
        c.close()
    conn.close()

    return render_template('stats.html',
        stats = proxy_connection_stats,
        totalHits = len(proxy_connection_stats),
        statName = 'Proxy attempts (sent Proxy-Connection header)',
        )

@main.route('/stats/headers/contains', methods = ['GET'])
@login_required
def header_string_search():
    """ Query for a certain string in headers.
    Usage: example.com/stats/headers/contains?header_string=<search_string> """
    header_string = request.args.get('header_string', '')
    header_string_q = '%' + header_string + '%'

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for headers containing the string
        sql_query = """
            SELECT * FROM bots WHERE (headers LIKE ?) ORDER BY id DESC;
        """
        data_tuple = (header_string_q,)
        c.execute(sql_query, data_tuple)
        headers_contains_stats = c.fetchall()
        c.close()
    conn.close()

    return render_template('stats.html',
        stats = headers_contains_stats,
        totalHits = len(headers_contains_stats),
        statName = f'In Headers: {header_string}',
        )

@main.route('/stats/hostname', methods = ['GET'])
@login_required
def hostname_stats():
    """ Get records matching (or ending with) the hostname. """
    hostname = request.args.get('hostname', '')
    hostname_q = '%' + hostname + '%'

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Using LIKE to include subdomains i.e. %.example.net
        sql_query = "SELECT * FROM bots WHERE (hostname LIKE ?) ORDER BY id DESC;"
        data_tuple = (hostname_q,)
        c.execute(sql_query, data_tuple)
        hostname_stats = c.fetchall()

        c.close()
    conn.close()

    flash('Note: Includes hostnames that are subdomains of the query.', 'info')
    return render_template('stats.html',
        stats = hostname_stats,
        totalHits = len(hostname_stats),
        statName = f'Hostname: {hostname}'
        )

@main.route('/stats/headers/pretty')
@login_required
def headers_single_pretty():
    """ Display a single request's headers on page in a more human-readable format. """

    request_id = request.args.get('id', '')
    next_request_id = int(request_id) + 1
    prev_request_id = int(request_id) - 1

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Select the single request from the db, by it's ID
        sql_query = "SELECT headers FROM bots WHERE id = ?;"
        data_tuple = (request_id,)
        c.execute(sql_query, data_tuple)
        try:
            saved_headers = c.fetchone()[0]
        except TypeError as e:
            flash('Bad request; ID doesn\'t exist.', 'error')
            return render_template('index.html')

        c.close()
    conn.close()

    #Recreate the dictionary from the saved data.
    '''Could maybe use json.dumps instead, but have to replace single quotes w/double;
    This breaks when there are header values that contain doublequotes. So what I really need is
    a better way of storing the headers in the database.'''

    recreated_dictionary = ast.literal_eval(saved_headers)
    
    #flash(f'Headers sent in Request #{request_id}', 'headersDictTitle')

    """
    for key, value in recreated_dictionary.items():
        flash(f'{key}: {value}', 'headersDictMessage')
    """

    return render_template('headers_single.html',
        stats = recreated_dictionary,
        request_id = request_id,
        next_request_id = next_request_id,
        prev_request_id = prev_request_id)

@main.route('/stats/id/<int:request_id>', methods = ['GET'])
@login_required
def stats_by_id(request_id):
    """ Get an individual request by ID#. """
    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Only need one result, but the stats page uses a dictionary so this is fine.
        sql_query = "SELECT * FROM bots WHERE id = ? LIMIT 1;"
        data_tuple = (request_id,)
        c.execute(sql_query, data_tuple)
        id_stats = c.fetchall()

        c.close()
    conn.close()

    return render_template('stats.html',
        stats = id_stats,
        #totalHits = len(id_stats),
        statName = f'ID: {request_id}')

@main.route('/stats/id/multiple', methods = ['GET'])
@login_required
def stats_by_id_multiple():
    """ Get more than one request by ID#. GLOB query.
    Usage: For ID#'s 100-199, use request_id=1?? """
    request_id = request.args.get('request_id', '')

    if not validate_id_query(request_id):
        flash('Bad request', 'errorn')
        try:
            return redirect(request.referrer)
        except:
            return render_template('index.html')

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT * FROM bots WHERE id GLOB ? ORDER BY id DESC;"
        data_tuple = (request_id,)
        c.execute(sql_query, data_tuple)
        id_stats = c.fetchall()

        c.close()
    conn.close()

    return render_template('stats.html',
        stats = id_stats,
        totalHits = len(id_stats),
        statName = f'ID: {request_id}')

@main.route('/admin/delete_single', methods = ['POST'])
@login_required
@admin_required
def delete_record_by_id():
    """ Delete an individual request by ID#. Admin only. """

    # Get the id# from the request args, and validate that it's numeric
    request_id = request.args.get('request_id')
    if not request_id.isnumeric():
        flash('ID# must be numeric', 'errorn')
        return redirect(request.referrer)

    # Delete the row from database
    with sqlite3.connect(requests_db) as conn:
        c = conn.cursor()
        # Delete the row with id = request_id
        sql_query = "DELETE FROM bots WHERE id = ?;"
        data_tuple = (request_id,)
        c.execute(sql_query, data_tuple)
        conn.commit()

        c.close()
    conn.close()

    # Log the action to systemd logs
    logging.info(f'Deleted request ID# {request_id} by user {current_user.username}')

    flash(f'Deleted request #{request_id}', 'successn')
    return redirect(request.referrer)

@main.route('/admin/delete_login', methods = ['POST'])
@login_required
@admin_required
def delete_login_record():
    """ Delete a login record by ID#. Admin only. """
    _id = request.args.get('login_id', '')
    # Get the id# from the request args, and validate that it's numeric
    if not _id.isnumeric():
        flash('ID# must be numeric', 'errorn')
        return redirect(request.referrer)

    with sqlite3.connect(requests_db) as conn:
        c = conn.cursor()
        sql_query = "DELETE FROM logins WHERE id = ?;"
        data_tuple = (_id,)
        c.execute(sql_query, data_tuple)
        c.close()
    conn.close()

    # Log the action to systemd logs
    logging.info(f'Deleted login record {_id} by user {current_user.username}')

    flash(f'Deleted login record #{_id}', 'successn')
    return redirect(request.referrer)

@main.route('/search', methods = ['GET'])
@login_required
def return_search_page():
    """ Return the search page. NOTE: Still working on a search page template, so won't quite work."""
    return render_template('search.html')

# this is ugly as fuck but it works for now i guess
@main.route('/search/parse', methods = ['GET'])
@login_required
def parse_search_form():
    """ Redirect to one of the other views, depending on which search was selected. """
    #logging.debug(request.args) #testing
    chosen_query = request.args.get('chosen_query', '')
    query_text = request.args.get('query_text', '')

    # Flash message if no query input
    if not query_text or query_text is None:
        flash('No query input', 'error')
        return render_template('search.html')

    if not chosen_query or chosen_query is None:
        flash('Must select a query.', 'error')
        return render_template('search.html')

    #Parse and redirect, based on which field was selected
    if chosen_query == 'ip_string':
        ip_string = query_text
        return redirect(url_for('main.ipStats', ipAddr = ip_string))
    if chosen_query == 'url':
        url = query_text
        url = '*' + url + '*'
        return redirect(url_for('main.urlStats', url = url))
    elif chosen_query == 'header_string':
        header_string = query_text
        return redirect(url_for('main.header_string_search', header_string = header_string))
    elif chosen_query == 'ua_string':
        ua_string = query_text
        ua_string = '%25' + ua_string + '%25'
        return redirect(url_for('main.uaStats', ua = ua_string))
    elif chosen_query == 'body_string':
        body_string = query_text
        body_string = '%' + body_string + '%'
        return redirect(url_for('main.bodyStats', body = body_string))
    elif chosen_query == 'hostname_string':
        hostname_string = query_text
        return redirect(url_for('main.hostname_stats', hostname = hostname_string))

# Misc routes

@main.route('/test/profile', methods = ['GET'])
@login_required
def profile():
    """ Profile route for testing login. """
    return render_template('profile.html', name=current_user.username)

@main.route('/test/admin', methods = ['GET'])
@login_required
@admin_required
def admin_test():
    """ For testing admin_required decorator. """
    flash('OK', 'successn')
    return render_template('index.html')

@main.route('/about', methods = ['GET'])
@login_required
def about():
    logging.debug(request)
    return render_template('about.html')

# Routes for security.txt + robots.txt
# Can also just serve them from Nginx
@main.route('/.well-known/security.txt')#Standard location
@main.route('/security.txt')
def securityTxt():
    """ Serve a security.txt in case Nginx isn't there to do it. """
    logging.debug(request)
    return send_from_directory('static', path='txt/security.txt')
@main.route('/robots.txt')
def robotsTxt():
    """ It's a honeypot, of course I want to allow bots. """
    logging.debug(request)
    return send_from_directory('static', path='txt/robots.txt')
@main.route('/favicon.ico', methods = ['GET'])
def serve_favicon():
    """ Serve the favicon (and stop saving requests for it). """
    logging.debug(request)
    return send_from_directory('static', path='favicon.ico')
