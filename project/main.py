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
from flask import request, redirect, url_for, render_template, jsonify, Response, send_from_directory, g, after_this_request, flash, Blueprint, current_app, make_response
from flask_login import login_required, current_user
from urllib.parse import parse_qs, unquote
from functools import wraps
from dateutil.parser import parse
from . import cache

main = Blueprint('main', __name__)
requests_db = 'bots.db'

# Initialize bots database
# Should move this to models.py as a sqlAlchemy model.
def createDatabase(): # note: change column names to just match http headers, this schema is stupid and confusing.
    """ Create the bots.db database that will contain all the requests data. """
    with sqlite3.connect(requests_db) as conn:
        c = conn.cursor()

        c.execute("""
            CREATE TABLE IF NOT EXISTS "bots" (
            "id"    INTEGER,
            "remoteaddr"	TEXT CHECK(length("remoteaddr") <= 64),
            "hostname"	TEXT CHECK(length("hostname") <= 4096),
            "useragent"	TEXT CHECK(length("useragent") <= 16384),
            "requestmethod"	TEXT CHECK(length("requestmethod") <= 8),
            "querystring"	TEXT,
            "time"	DATETIME CHECK(length("time") <= 1024),
            "postjson"	TEXT,
            "headers"	TEXT,
            "headers_json"	TEXT,
            "url"	TEXT,
            "reported"	NUMERIC CHECK(length("reported") <= 1),
            "contenttype"	TEXT CHECK(length("contenttype") <= 16384),
            "country"	TEXT CHECK(length("country") <= 3),
            "from_contact"	TEXT CHECK(length("from_contact") <= 16384),
            "scheme"	TEXT CHECK(length("scheme") <= 5),
            "host"	TEXT CHECK(length("host") <= 16384),
            "path"	TEXT,
            "referer"	TEXT CHECK(length("referer") <= 16384),
            PRIMARY KEY("id")
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

### Validation

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

# Validate CIDR
def validate_cidr(_cidr_net):
    """ Validate CIDR input. Not perfect, but better than nothing. """
    # IPv4/v6 chars + /
    cidr_pattern = r'^[0-9A-Fa-f\.:\/]{1,43}$'
    regex = re.compile(cidr_pattern)
    if regex.match(_cidr_net):
        return True
    else:
        return False

def validate_id_query(_id):
    """ Validate queried ID # (for GLOB queries). """
    # Numbers + GLOB chars. Loose max length to account for glob queries.
    id_pattern = r'^[0-9*\[\]\-^?]{1,24}$'
    regex = re.compile(id_pattern)
    if regex.match(_id):
        return True
    else:
        return False

def validate_id_numeric(_id):
    """ Validate queried ID #. (Numeric) """
    # Numberic
    id_numeric_pattern = r'^[0-9]{1,32}$'
    regex = re.compile(id_numeric_pattern)
    if regex.match(_id):
        return True
    else:
        return False

### SQLite function callbacks

#Callback for SQLite CIDR user function    
def cidr_match(item, subnet):
    """ Callback for SQLite user function. Usage: SELECT * FROM bots WHERE CIDR(remoteaddr, ?) """
    try:
        subnet_conv = ipaddress.ip_network(subnet, strict=False)
        ip_conv = ipaddress.ip_address(item)
        return ip_conv in subnet_conv
    except ValueError as e:
        return False

#Callback for SQLite REGEXP function
def regexp(expr, item):
    reg = re.compile(expr)
    return reg.search(str(item)) is not None

#Callback for SQLite compare_time custom function
def compare_time(timestamp, num_days):
    """True if timestamp is within the past <num_days> days. """
    current_time = datetime.datetime.now(datetime.timezone.utc)
    timestamp = parse(timestamp)
    timestamp_p = timestamp.astimezone(datetime.timezone.utc)
    #one_day = datetime.timedelta(days=7)
    difference = current_time - timestamp_p
    #logging.debug(difference)
    return abs(difference) < datetime.timedelta(days=num_days)

def compare_time_b(timestamp, num_days):
    """True if timestamp is within the past <num_days> days. """
    current_time = datetime.datetime.now(datetime.timezone.utc)
    cutoff = current_time - datetime.timedelta(days=num_days)
    timestamp_p = parse(timestamp).astimezone(datetime.timezone.utc)
    return timestamp_p > cutoff

### Define Flask app routes

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
        req_hostname = ''
        logging.debug(f'No hostname available, or no connection: {str(e)}')

    req_user_agent = request.headers.get('User-Agent', '')
    req_method = request.method
    req_query = request.query_string.decode('utf-8', errors='replace')
    #Timestamp compatible with ApuseIPDB API
    req_time = datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()
    req_headers = dict(request.headers) # go ahead and save the full headers
    if 'Cookie' in req_headers:
        req_headers['Cookie'] = '[REDACTED]' # Don't expose session cookies! Will be displayed later.
    headers_json = json.dumps(req_headers)
    req_country_code = request.headers.get('Cf-Ipcountry', '')
    req_from_contact = request.headers.get('From', '')
    req_scheme = request.scheme
    req_host = request.host
    req_path = request.path
    req_referer = request.headers.get('Referer', '')
    #add to db schema later
    req_args_j = json.dumps(request.args)

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
                req_body = request.get_data().decode('utf-8', errors = 'replace')
        elif 'application/x-www-form-urlencoded' in req_content_type:
            # If content-type is Form data. 
            if isinstance(request.get_data(), bytes):
                """If body is bytes: try utf-8 first, if that doesn't work then latin-1.
                Should add database column later for blob of original body, + which codec worked. """
                try:
                    logging.debug('Form data is bytes. Attempting to decode as utf-8...')
                    req_body = request.get_data().decode('utf-8')
                except UnicodeDecodeError:
                    try:
                        logging.debug('Attempting to decode as latin-1...')
                        req_body = request.get_data().decode('latin-1')
                    except UnicodeDecodeError:
                        logging.debug('Just use replacement chars if utf-8 or latin-1 dont work.')
                        req_body = request.get_data().decode('utf-8', errors = 'replace')

                """try: #After decoding, try to serialize again, if can't then leave it as-is
                    logging.debug('Attempting to serialize decoded body...')
                    body_dict = parse_qs(req_body) #parse into a dict
                    logging.debug(f'parsed dict: {body_dict}') #testing
                    if len(body_dict) > 0:
                        req_body = json.dumps(body_dict)
                except Exception as e:
                    logging.debug(f'Serializing decoded form data failed (saving as-is): {str(e)}')
                    pass"""
            else:
                """ If not bytes, either serialize it if possible, or decode. """
                try:
                    logging.debug('Serialize form data...')
                    req_body = json.dumps(dict(request.form)) #This is resulting in an empty string if it can't parse it
                except TypeError as e:
                    logging.debug('Form data not serializable, trying get_data()...')
                    req_body = request.get_data().decode('utf-8', errors = 'replace')
        elif 'text/html' in req_content_type or 'text/plain' in req_content_type:
            logging.debug('content-type: text/html or text/plain')
            req_body = request.get_data().decode('utf-8', errors = 'replace')
        else: #Any other content-type, or if no content-type declared
            try:
                req_body = request.get_data().decode('utf-8')
            except UnicodeDecodeError:
                req_body = request.get_data().decode('utf-8', errors = 'replace')
    except Exception as e:
        #If any other exceptions
        logging.error(f'Uncaught exception while trying to parse body. Saving with replacement chars. : {str(e)}')
        #req_body = str(e) #See if anything is still failing
        req_body = request.get_data().decode('utf-8', errors='replace')

    # Check request against detection rules, and submit report
    # Adding try/except temporarily while I test some things
    try:
        reported = check_all_rules() #see auto_report.py
    except Exception as e:
        logging.error(f'Error while executing detections: {str(e)}')
        reported = 0

    # Request data to insert into the database
    sql_query = """INSERT INTO bots
        (id,remoteaddr,hostname,useragent,requestmethod,querystring,time,postjson,headers,headers_json,url,reported,contenttype,country,from_contact,scheme,host,path,referer)
        VALUES (NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"""
    data_tuple = (req_ip,
                req_hostname,
                req_user_agent,
                req_method,
                req_query,
                req_time,
                req_body,
                str(req_headers),
                headers_json,
                req_url,
                reported,
                req_content_type,
                req_country_code,
                req_from_contact,
                req_scheme,
                req_host,
                req_path,
                req_referer)

    @after_this_request
    def closeConnection(response):
        """ Add response code to the tuple, commit and close db connection. """
        with sqlite3.connect(requests_db) as conn:
            c = conn.cursor()
            c.execute(sql_query, data_tuple)
            conn.commit()
        conn.close()

        #Clear the cache so this request can be shown on main.stats
        cache.clear()

        #logging.debug(response.status) #For testing
        return response

    flash(f'IP: {req_ip}', 'info')
    return render_template('index.html')

@main.route('/stats')
@login_required
@cache.cached(timeout=60)
def stats():
    """ Pull the most recent requests from bots.db and pass data to stats template to display. """
    records_limit = request.args.get('limit') or '100000' # Limit to # of records to prevent DOS

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
        sql_query = "SELECT COUNT(*) FROM bots;"
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

        #Get most common IP of past 7 days
        conn.create_function("COMPARETIME", 2, compare_time_b)
        sql_query = """
            SELECT remoteaddr, COUNT(*) AS count
            FROM bots
            WHERE COMPARETIME(time, 7)
            GROUP BY remoteaddr
            ORDER BY count DESC, MAX(id) DESC
            LIMIT 1;
            """
        c.execute(sql_query)
        top_ip_weekly = c.fetchone()

        #Get top IP of past 24 hours
        sql_query = """
            SELECT remoteaddr, COUNT(*) AS count
            FROM bots
            WHERE COMPARETIME(time, 1)
            GROUP BY remoteaddr
            ORDER BY count DESC, MAX(id) DESC
            LIMIT 1;
            """
        c.execute(sql_query)
        top_ip_daily = c.fetchone()

        c.close()
    conn.close()

    #pagination
    import math
    page = int(request.args.get('page', 1))
    items_per_page = 256
    total_items = len(stats)
    total_pages = math.ceil(total_items / items_per_page)
    start_index = (page - 1) * items_per_page
    end_index = min(start_index + items_per_page, total_items)

    stats_on_page = stats[start_index:end_index]

    return render_template('stats.html',
        #stats = stats,
        stats = stats_on_page, #pagination
        page = page,#pagination
        total_pages = total_pages,#pagination
        totalHits = totalHits,
        #statName = f'Most Recent {records_limit} HTTP Requests',
        statName = 'Most recent HTTP requests',
        top_ip = top_ip,
        top_ip_weekly = top_ip_weekly,
        top_ip_daily = top_ip_daily,
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

@main.route('/stats/subnet', methods = ['GET'])
@login_required
def subnet_stats():
    """ Get requests from a CIDR subnet, using SQL user function (callback to cidr_match()). """
    test_subnet = request.args.get('net', '')
    
    # Validate
    try:
        ipaddress.ip_network(test_subnet, strict=False)
    except ValueError as e:
        logging.error(f'Invalid CIDR: {str(e)}')
        return ('Bad request: Must be a valid CIDR subnet.', 400)

    """ Get rows that came from a given CIDR subnet. """
    with sqlite3.connect(requests_db) as conn:
        #create user function, have to create it each time the connection is created
        conn.create_function("CIDR", 2, cidr_match)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT * FROM bots WHERE CIDR(remoteaddr, ?) ORDER BY id DESC LIMIT 10000;"
        data_tuple = (test_subnet,)
        try:
            c.execute(sql_query, data_tuple)
        except Exception as e:
            logging.error(f'{str(e)}')
            #flash('invalid input', 'errorn')
            return redirect(url_for('main.index'))
        subnet_stats = c.fetchall()

        c.close()
    conn.close()

    flash('Note: Limited to 10000 results.', 'info')
    return render_template('stats.html',
        stats = subnet_stats,
        totalHits = len(subnet_stats),
        statName = f'CIDR Subnet: {test_subnet}')

@main.route('/stats/ip/topten', methods = ['GET'])
@login_required
def top_ten_ips():
    """ Return top ten most common IPs. """
    _num_of_ips = request.args.get('limit', '10') # num of IPs to include, i.e. Top X IPs. default 10
    if not _num_of_ips.isnumeric():
        flash('Bad request: `limit` must be numeric', 'error')
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

    flash('Note: Use * for wildcard, i.e. url=*.example.com/*', 'info')
    return render_template('stats.html',
        stats = urlStats,
        totalHits = len(urlStats),
        statName = f"URL: {url}"
        )

@main.route('/stats/path', methods = ['GET'])
@login_required
def path_stats():
    """ Get rows matching the Path. """
    path = request.args.get('path', '')
    #path_q = '%' + path + '%'

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching path
        sql_query = """
            SELECT * FROM bots WHERE (path LIKE ?) ORDER BY id DESC;
            """
        data_tuple = (path,)
        c.execute(sql_query, data_tuple)
        path_stats = c.fetchall()
        c.close()
    conn.close()

    flash('Note: Use % for wildcard, i.e. path=/admin/%', 'info')
    return render_template('stats.html',
        stats = path_stats,
        totalHits = len(path_stats),
        statName = f"PATH: {path}"
        )

@main.route('/stats/host', methods = ['GET'])
@login_required
def host_stats():
    """ Get rows matching the Host. """
    host = request.args.get('host', '')

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching host
        sql_query = """
            SELECT * FROM bots WHERE (host LIKE ?) ORDER BY id DESC;
            """
        data_tuple = (host,)
        c.execute(sql_query, data_tuple)
        host_stats = c.fetchall()
        c.close()
    conn.close()

    return render_template('stats.html',
        stats = host_stats,
        totalHits = len(host_stats),
        statName = f"Host: {host}"
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

    flash('Note: LIKE query- %25 for wildcard', 'info')
    return render_template('stats.html',
        stats = bodyStats,
        totalHits = len(bodyStats),
        statName = f"Request Body",
        subtitle = f'{body}',
        )

@main.route('/stats/content-type', methods = ['GET'])
@login_required
def content_type_stats():
    """ Get rows matching the Content-Type. """
    ct = request.args.get('ct', '')
    #ct_q = ct + '%'

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for matching Content-Type
        #sql_query = """SELECT * FROM bots WHERE (contenttype LIKE ?) ORDER BY id DESC;"""
        '''Query content-type from the headers_json column, until I update the db;
        anything before Feb. 17 will = None. '''
        sql_query = """
            SELECT *
            FROM bots
            WHERE JSON_EXTRACT(headers_json, '$.Content-Type') LIKE ?
            ORDER BY id DESC;
            """
        data_tuple = (ct,)
        c.execute(sql_query, data_tuple)
        ct_stats = c.fetchall()
        c.close()
    conn.close()

    return render_template('stats.html',
        stats = ct_stats,
        totalHits = len(ct_stats),
        statName = f"Content-Type: {ct}",
        )

@main.route('/stats/date', methods = ['GET'])
@login_required
def date_stats():
    """ Get records from the same day.
    Usage: Slice the timestamp before querying this route; 10chars=date, 13chars=hour, 16chars=min """
    date = request.args.get('date', '') #A timestamp matching the db timestamp format
    accuracy: int = int(request.args.get('accuracy', 10)) #string index to slice the timestamp to before querying db

    date_q_str = date[0:accuracy] #string to display on stats.html
    date_q = date[0:accuracy] + '%'
    #date_day = date[0:10] + '%' #First 10 chars of timestamp = date as yyyy-dd-mm; +wildcard = sql
    #date_x = date + '%' #If date arg (timestamp) has already been sliced
    #logging.debug(date_q) #testing

    # Set UOM to display on stats page
    if accuracy == 10:
        u_of_m = 'day'
    elif accuracy == 13:
        u_of_m = 'hour'
    elif accuracy == 16:
        u_of_m = 'minute'
    else:
        u_of_m = 'custom'

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query where timestamp matches date_q
        sql_query = """
            SELECT * FROM bots WHERE (time LIKE ?) ORDER BY id DESC;
            """
        data_tuple = (date_q,)
        c.execute(sql_query, data_tuple)
        date_stats = c.fetchall()
        c.close()
    conn.close()

    return render_template('stats.html',
        stats = date_stats,
        totalHits = len(date_stats),
        statName = f"Time: {date}",
        subtitle = f'Accuracy: {u_of_m} - {date_q}',
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
        if top_reported:
            top_reported_ip_count = top_reported['count']
            top_reported_ip_addr = top_reported['remoteaddr']

        c.close()
    conn.close()

    # Flash a message based on reported or unreported
    if reported_status == '1' and top_reported:
        top_reported_ip_message = f'Most reported IP: {top_reported_ip_addr}, reported {top_reported_ip_count} times.'
    elif reported_status == '0' and top_reported:
        top_reported_ip_message = f'Most un-reported IP: {top_reported_ip_addr} - {top_reported_ip_count} requests not reported.'
    else:
        top_reported_ip_message = 'Nothing has been reported.' #To prevent UnboundLocalError

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
    Usage: /stats/headers/contains?header_string=<search_string> """
    header_string = request.args.get('header_string', '')
    header_string_q = '%' + header_string + '%'

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Query for headers containing the string
        sql_query = """SELECT * FROM bots
            WHERE (headers_json LIKE ?)
            ORDER BY id DESC
            LIMIT 50000;"""
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
    hostname_q = '%' + hostname

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

@main.route('/stats/headers/single/<request_id>', methods = ['GET'])
@login_required
def headers_single_json(request_id):
    """ Pull headers from db by ID#, and display on headers_json.html. """

    if not request_id or not request_id.isnumeric():
        return ('Bad request: ID must be numeric.', 400)

    request_id = int(request_id)
    next_request_id = request_id + 1
    prev_request_id = request_id - 1

    #pull headers from db
    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        # Select the single request from the db, by it's ID
        sql_query = "SELECT headers_json FROM bots WHERE id = ?;"
        data_tuple = (request_id,)
        c.execute(sql_query, data_tuple)
        try:
            saved_headers = c.fetchone()[0]
        except TypeError as e:
            flash('Bad request; ID doesn\'t exist.', 'error')
            return render_template('index.html')

        #Get an individual header value:
        #sql_query = "SELECT JSON_EXTRACT(headers_json, '$.Host') AS host FROM bots WHERE id = ?;"
        #c.execute(sql_query, data_tuple)
        #data_host = c.fetchone()['host']
        #logging.debug(f'HOST: {data_host}')
        c.close()
    conn.close()

    try:
        data = json.loads(saved_headers)
    except TypeError as e:
        # Catch TypeError when headers_json field is NULL (i.e. database isn't updated)
        # Only need this until I update the existing database.
        flash('Bad request; ID doesn\'t exist.', 'error')
        return render_template('index.html')

    #logging.debug(f'Request headers: {data}')

    return render_template('headers_json.html',
        stats = data,
        request_id = request_id,
        next_request_id = next_request_id,
        prev_request_id = prev_request_id
        )

@main.route('/stats/headers/key_search', methods = ['GET'])
@login_required
def headers_key_search():
    """ Find requests with a given header. """
    header_name = request.args.get('key', 'no input')
    #query db
    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = """SELECT *
                    FROM bots
                    WHERE (JSON_EXTRACT(headers_json, ?)) IS NOT NULL
                    ORDER BY id DESC
                    LIMIT 10000;
                    """
        data_tuple = (f'$.{header_name}',)
        c.execute(sql_query, data_tuple)
        try:
            results = c.fetchall()
        except TypeError as e:
            flash(f'{str(e)}', 'error')
            return render_template('index.html')

        #Get an individual header value:
        #sql_query = "SELECT JSON_EXTRACT(headers_json, '$.Host') AS host FROM bots WHERE id = ?;"
        #c.execute(sql_query, data_tuple)
        #data_host = c.fetchone()['host']
        #logging.debug(f'HOST: {data_host}')
        c.close()
    conn.close()

    flash('Note: Limited to 10k results', 'info')
    return render_template('stats.html',
        stats = results,
        statName = f'In header keys: {header_name}',
        totalHits = len(results)
        )

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

    if not id_stats:
        return ({'Bad request': 'ID doesn\'t exist.'}, 400)

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

@main.route('/search/all', methods = ['GET'])
@login_required
def full_search():
    """ Search entire db (all fields) for given string. """
    q = request.args.get('q', '')
    q = '%' + q + '%'

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        #conn.create_function("REGEXP", 2, regexp)
        c = conn.cursor()
        
        #Get column names
        sql_query = "PRAGMA table_info(bots)"
        c.execute(sql_query)
        columns = [column[1] for column in c.fetchall()]

        sql_query = "SELECT * FROM bots WHERE "
        conditions = [f"{column} LIKE ?" for column in columns]
        #conditions = [f"{column} REGEXP ?" for column in columns] #If using regexp over LIKE
        sql_query += ' OR '.join(conditions)
        sql_query += ' ORDER BY id DESC;'
        #data_list = [q for i in range(len(columns))]
        data_list = [q for i in enumerate(columns)]
        c.execute(sql_query, data_list)
        results = c.fetchall()

        c.close()
    conn.close()

    return render_template('stats.html',
        stats = results,
        totalHits = len(results),
        statName = f'Full db search',
        subtitle = q,
        )

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
    """ Return the search page. NOTE: Still working on a search page template."""
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
    elif chosen_query == 'cidr_string':
        cidr_string = query_text
        return redirect(url_for('main.subnet_stats', net = cidr_string))
    elif chosen_query == 'url':
        url = query_text
        url = '*' + url + '*'
        return redirect(url_for('main.urlStats', url = url))
    elif chosen_query == 'header_string':
        header_string = query_text
        return redirect(url_for('main.header_string_search', header_string = header_string))
    elif chosen_query == 'header_key':
        header_key = query_text.strip().title()
        return redirect(url_for('main.headers_key_search', key = header_key))
    elif chosen_query == 'content_type':
        ct = query_text.strip()
        ct = '%' + ct + '%'
        return redirect(url_for('main.content_type_stats', ct = ct))
    elif chosen_query == 'ua_string':
        ua_string = query_text
        ua_string = '%25' + ua_string + '%25'
        return redirect(url_for('main.uaStats', ua = ua_string))
    elif chosen_query == 'body_string':
        body_string = query_text
        body_string = '%' + body_string + '%'
        return redirect(url_for('main.bodyStats', body = body_string))
    elif chosen_query == 'hostname_endswith':
        hostname_string = query_text.strip()
        return redirect(url_for('main.hostname_stats', hostname = hostname_string))
    elif chosen_query == 'hostname_contains':
        hostname_string = query_text.strip()
        hostname_string = hostname_string + '%'
        return redirect(url_for('main.hostname_stats', hostname = hostname_string))
    elif chosen_query == 'any_field':
        q = query_text
        return redirect(url_for('main.full_search', q = q))

# Misc routes

@main.route('/test/regexp', methods = ['GET'])
@login_required
def test_regexp():
    """ Test regex. Get a record by id#.
    Reference: https://stackoverflow.com/a/5365533 """
    request_id = '10000'
    #Callback for SQLite REGEXP function
    '''def regexp(expr, item):
        reg = re.compile(expr)
        return reg.search(str(item)) is not None'''

    """ Get an individual request by ID#. """
    with sqlite3.connect(requests_db) as conn:
        #create regexp function, have to create it each time connection is created
        conn.create_function("REGEXP", 2, regexp)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT * FROM bots WHERE id REGEXP (?);"
        data_tuple = (request_id,)
        c.execute(sql_query, data_tuple)
        id_stats = c.fetchall()

        c.close()
    conn.close()

    return render_template('stats.html',
        stats = id_stats,
        totalHits = len(id_stats),
        statName = f'ID: {request_id}')

@main.route('/test/recently_reported', methods = ['GET'])
@login_required
def is_already_reported():
    """ Check whether IP has been reported within past day. """
    ip_to_check = request.args.get('ip', '')
    if not ip_to_check:
        return ({'error':'no input given'}, 400)
    current_time = datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()
    one_day_delta = datetime.timedelta(days=1)

    #Retrieve timestamp of the last hit from ip that was reported
    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        #Only need time for this function, but select * so I can use the other columns for things
        sql_query = """SELECT * FROM bots
            WHERE remoteaddr LIKE ? AND reported = 1
            ORDER BY id DESC
            LIMIT 1;"""
        data_tuple = (ip_to_check,)
        c.execute(sql_query, data_tuple)
        last_reported_hit = c.fetchone()
        c.close()
    conn.close()

    #Compare timestamp to current time
    if last_reported_hit:
        last_reported_time = last_reported_hit['time']
        logging.debug(f'Last reported time: {last_reported_time}')
        #logging.debug(f'Last reported request: {last_reported_hit["requestmethod"]} {last_reported_hit["url"]}')
        current_time_parsed = parse(current_time)
        last_reported_time_parsed = parse(last_reported_time)

        time_difference = current_time_parsed - last_reported_time_parsed
        #logging.debug(f'Difference: {time_difference}')
        if abs(time_difference) < one_day_delta:
            #logging.debug('True')
            return (['True', last_reported_time_parsed], 200)
        else:
            #logging.debug('False')
            return (['False', f'Last reported {last_reported_time_parsed}'], 200)
    return (['False', 'IP never reported.'], 200)

#Test setting style preference
@main.route('/profile/set_theme', methods = ['POST'])
@login_required
def set_pref_theme():
    """ Set cookie containing preferred color scheme. """
    theme = request.form['pref_theme']
    #resp = make_response(redirect(request.referrer))
    resp = make_response(redirect('#'))
    resp.set_cookie('pref_theme', value = theme, path = '/', httponly = True)
    return resp

#Test getting style preference
@main.route('/profile/get_theme', methods = ['GET'])
@login_required
def get_pref_theme():
    """ Return user's preferred color theme; used by JS function to apply the
    theme (class) to <body> element on cached pages that otherwise would still have
    the previous theme attached. """
    theme = request.cookies.get('pref_theme')
    return theme

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
    return send_from_directory('static/txt', path='security.txt')
@main.route('/robots.txt')
def robotsTxt():
    """ It's a honeypot, of course I want to allow bots. """
    logging.debug(request)
    return send_from_directory('static/txt', path='robots.txt')
@main.route('/favicon.ico', methods = ['GET'])
def serve_favicon():
    """ Serve the favicon (and stop saving requests for it). """
    logging.debug(request)
    return send_from_directory('static', path='favicon.ico')
