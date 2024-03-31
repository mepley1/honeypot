""" Analysis routes & functions. May return an image, data etc.
These are very much a work in progress. """

import datetime
import ipaddress
#import json
import logging
import sqlite3
import re
import base64
from io import BytesIO
from .auto_report import get_real_ip
from flask import flash, redirect, render_template, request, jsonify, Blueprint, current_app, Flask
from flask_login import login_required
from functools import wraps
from dateutil.parser import parse
from matplotlib.figure import Figure
from matplotlib.pyplot import set_loglevel as set_pyplot_loglevel
from matplotlib.pyplot import cycler
from . import cache

analysis = Blueprint('analysis', __name__)
requests_db = 'bots.db'


#Set autolayout for matplotlib plots
from matplotlib import rcParams
rcParams.update({'figure.autolayout': True,
                'figure.facecolor': '#D2D4D3',
                #'figure.dpi': '120', #default: 100
                #'figure.figsize': [6.4, 4.8], #default: 6.4, 4.8
                'font.family': ['sans-serif'],
                'axes.facecolor': '#D2D4D3',
                'axes.labelcolor': '#111828',
                'axes.titlecolor': '#111828',
                'grid.color': '#b2b4b3',
                'grid.alpha': '0.6',
                'lines.marker': '.', #https://matplotlib.org/stable/api/markers_api.html
                'xtick.color': '#111828',
                'xtick.labelcolor': '#111828',
                'ytick.color': '#111828',
                'ytick.labelcolor': '#111828',
                'axes.prop_cycle': cycler(color=['#2563ea','#3bc14a','#ff7f02','slateblue','darkturquoise','#0f8a1e','#bb2020','indigo'])
                })
set_pyplot_loglevel(level = 'warning') #shut up matplotlib

#bar_color = '#2563EA'
bar_color = '#3BC14A'

@analysis.context_processor
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

### SQLite function callbacks

#Callback for SQLite CIDR user function    
def cidr_match(item, subnet):
    """ Callback for SQLite user function. Usage: SELECT * FROM bots WHERE CIDR(remoteaddr, ?) """
    try:
        subnet_conv = ipaddress.ip_network(subnet)
        try:
            ip_conv = ipaddress.ip_address(item)
        except Exception as e:
            logging.error(f'exception in cidr_match: {str(e)}')
        return ip_conv in subnet_conv
    except ValueError as e:
        return False

#Callback for SQLite REGEXP function
def regexp(expr, item):
    reg = re.compile(expr)
    return reg.search(str(item)) is not None

#Callback for SQLite COMPARETIME custom function
def compare_time_b(timestamp, num_days):
    """True if timestamp is within the past <num_days> days. """
    current_time = datetime.datetime.now(datetime.timezone.utc)
    cutoff = current_time - datetime.timedelta(days=num_days)
    timestamp_p = parse(timestamp).astimezone(datetime.timezone.utc)
    return timestamp_p > cutoff

#This is VERY SLOW, don't use it for huge queries.
def between_dates(item, startdate, enddate):
    """ True if item is between <startdate> and <enddate> """
    item = parse(item).astimezone(datetime.timezone.utc)
    #item = datetime.datetime.fromisoformat(item)
    startdate = parse(startdate).astimezone(datetime.timezone.utc)
    enddate = parse(enddate).astimezone(datetime.timezone.utc)
    return startdate <= item < enddate

### Routes

@analysis.route('/stats/total_per_day/<int:num_of_days>')
@login_required
def total_per_day(num_of_days):
    """ Return total # of hits per day. """
    #Initialize lists I'll use
    hits_per_day = [] #Will hold the total # of hits
    date_labels = [] #date ticks for x-axis matplotlib
    dates = []
    start_date = datetime.datetime.now() - datetime.timedelta(days=num_of_days)
    #start_date_str = start_date.strftime('%b %d %Y') #For matplotlib graph title
    logging.debug(f'Totals since: {start_date}') #testing
    end_date = start_date + datetime.timedelta(days=1)
    for i in range(0, num_of_days + 1):
        date_to_append = start_date + datetime.timedelta(days=i)
        date_to_append_str = date_to_append.strftime('%Y-%m-%d')
        dates.append(date_to_append_str)
    logging.debug(f'Dates: {dates}')

    # Query db
    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        #Query each date, append total to hits_per_day
        for date in dates:
            sql_query = """
                SELECT COUNT(*) AS count
                FROM bots
                WHERE time GLOB ?;
                """
            data_tuple = (f'{date}*',) #Date string, + wildcard appended
            c.execute(sql_query, data_tuple)
            hits_that_day = c.fetchall()[0]['count']
            logging.info(f'{date}: {hits_that_day}')
            hits_per_day.append(hits_that_day)
            date_labels.append(datetime.datetime.strptime(date, '%Y-%m-%d').strftime('%b %d'))

        c.close()
    conn.close()

    daily_avg = sum(hits_per_day) / num_of_days
    results = list(zip(dates, hits_per_day)) #list of tuples to pass to analys_stats

    # Generate the figure **without using pyplot**.
    fig = Figure()
    ax = fig.subplots()
    ax.plot(date_labels, hits_per_day)
    #ax.text(0, 0, "Total per day", fontsize=16)
    ax.set_title(f'Hits per day {date_labels[0]} - {date_labels[-1]}')
    #ax.suptitle(f'Avg. {daily_avg} hits/day') #wrong, suptitle dont exist
    ax.set_xlabel('Date')
    ax.set_ylabel('Total hits')

    #ax.set_ylim(0, 500) #limit y-axis to soften outliers
    ax.grid(True)

    # rotate x-axis labels for readability
    for tick in ax.get_xticklabels():
        tick.set_rotation(90)
        tick.set_fontsize(8)
        #tick.set_fontfamily('Hack')
    # Smaller font size for large # of days. For readability
    if num_of_days > 30:
        for tick in ax.get_xticklabels():
            tick.set_fontsize(6)

    # Save it to a temporary buffer.
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plot_image = base64.b64encode(buf.getbuffer()).decode("ascii")

    return render_template('stats.html',
        statName = f'Total hits by date',
        subtitle = f'{date_labels[0]} - {date_labels[-1]}',
        image_data = plot_image,
        analys_stats = results,
        analys_titles = ['Date', 'Total hits'],
        )

@analysis.route('/stats/ip/per_day')
@login_required
def ip_per_day():
    """ Return total # of hits per day from given IP. """
    #note: List of hosts() in ipaddress.ip_network: https://docs.python.org/3/howto/ipaddress.html
    
    num_of_days = int(request.args.get('days', '7'))
    ip = request.args.get('ip', '*')

    #Initialize lists I'll use
    hits_per_day = [] #Will hold the total # of hits
    date_labels = [] #date ticks for x-axis matplotlib
    dates = []
    start_date = datetime.datetime.now() - datetime.timedelta(days=num_of_days)
    #start_date_str = start_date.strftime('%b %d %Y') #For matplotlib graph title
    logging.debug(f'Totals since: {start_date} for IP {ip}') #testing
    end_date = start_date + datetime.timedelta(days=1)

    # Dates to use in queries loop
    for i in range(0, num_of_days + 1):
        date_to_append = start_date + datetime.timedelta(days=i)
        date_to_append_str = date_to_append.strftime('%Y-%m-%d')
        dates.append(date_to_append_str)
    #logging.debug(f'Dates: {dates}')

    # Query db
    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        #Query each date, append total to hits_per_day
        for date in dates:
            sql_query = """
                SELECT COUNT(*) AS count
                FROM bots
                WHERE time GLOB ? AND remoteaddr GLOB ?;
                """
            data_tuple = (f'{date}*', ip) #Date string, + wildcard appended
            c.execute(sql_query, data_tuple)
            hits_that_day = c.fetchall()[0]['count']
            logging.info(f'{date}: {hits_that_day}')
            hits_per_day.append(hits_that_day)
            date_labels.append(datetime.datetime.strptime(date, '%Y-%m-%d').strftime('%b %d'))

        c.close()
    conn.close()

    daily_avg = sum(hits_per_day) / num_of_days #avg hits/day
    daily_avg = round(daily_avg, 1)

    #list of tuples to pass to analys_stats in stats.html (imitate sqlite3 results object)
    results = list(zip(date_labels, hits_per_day))
    #logging.debug(results)

    # Generate the figure **without using pyplot**.
    fig = Figure()
    ax = fig.subplots()
    ax.plot(date_labels, hits_per_day)
    #ax.text(0, 0, "Total per day", fontsize=16)
    ax.set_title(f'{ip} per day {date_labels[0]} - {date_labels[-1]}')
    #ax.suptitle(f'Avg. {daily_avg} hits/day') #wrong, suptitle dont exist
    ax.set_xlabel('Date')
    ax.set_ylabel('Total hits')

    #ax.set_ylim(0, 500) #limit y-axis to soften outliers
    ax.grid(True, zorder=0)

    # rotate x-axis labels for readability
    for tick in ax.get_xticklabels():
        tick.set_rotation(90)
        tick.set_fontsize(8)
    
    #Set font size slightly smaller for high # of days, for readability
    if num_of_days > 30:
        for tick in ax.get_xticklabels():
            tick.set_fontsize(6)

    # Save it to a temporary buffer.
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plot_image = base64.b64encode(buf.getbuffer()).decode("ascii")

    flash(f'Daily avg: {daily_avg}', 'info')
    flash('Note: Use * for wildcard i.e. 1.2.3.*', 'info')
    return render_template('stats.html',
        statName = f'Hits by IP per day',
        subtitle = f'IP: {ip} over {num_of_days} days',
        image_data = plot_image,
        analys_stats = results,
        analys_titles = ['Date', 'Count'],
        )

# Top Ten things

@analysis.route('/analysis/url/topten', methods = ['GET'])
@login_required
def top_ten_urls():
    """ Return top ten most common URLs. """
    _num_of_urls = request.args.get('limit', 10) # num of IPs to include, i.e. Top X IPs. default 10
    if not isinstance(_num_of_urls, int):
        flash('Bad request: `limit` must be type int', 'error')
        return render_template('index.html')

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT url, COUNT(*) AS count FROM bots GROUP BY url ORDER BY count DESC LIMIT ?;"
        # Execute the SQL query to get the 10 most common remoteaddr values
        data_tuple = (_num_of_urls,)
        c.execute(sql_query, data_tuple)
        top_urls = c.fetchall()

        # Now query for all requests for top URLs
        top_urls_list = [row['url'] for row in top_urls]
        logging.debug(f'Top URLs: {top_urls_list}') #testing, delete this

        sql_query = f"SELECT * FROM bots WHERE url IN ({ ','.join(['?']*len(top_urls_list)) }) ORDER BY id DESC;"
        c.execute(sql_query, top_urls_list)
        results = c.fetchall()

        c.close()
    conn.close()

    # Print the results
    for row in top_urls:
        flash(f'URL: {row["url"]}, Count: {row["count"]}', 'info')
    return render_template('stats.html',
        #stats = results,
        totalHits = len(results),
        statName = f'Top {_num_of_urls} most common URLs',
        )

@analysis.route('/analysis/path/topten', methods = ['GET'])
@login_required
def top_ten_paths():
    """ Return top ten most common paths. """
    _num_of_paths = request.args.get('limit', '10') # num of paths to include, i.e. Top X paths. default 10

    if not _num_of_paths.isnumeric():#validate
        flash('Bad request: `limit` must be numeric', 'error')
        return render_template('index.html')

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT path, COUNT(*) AS count FROM bots GROUP BY path ORDER BY count DESC LIMIT ?;"
        # get the 10 most common remoteaddr values
        data_tuple = (_num_of_paths,)
        c.execute(sql_query, data_tuple)
        top_paths = c.fetchall()

        top_paths_list = [row['path'] for row in top_paths]
        top_paths_counts = [row['count'] for row in top_paths]
        #logging.debug(f'Top paths: {top_paths_list}') #testing
        #logging.debug(f'Top path counts: {top_paths_counts}')

        #delete null item to avoid error (rows where there's no data, before I started saving paths)
        for i in reversed(range(len(top_paths_list))):
            if top_paths_list[i] is None:
                del top_paths_list[i]
                del top_paths_counts[i]
        #select all rows where path is a top10 one
        sql_query = f"SELECT * FROM bots WHERE path IN ({ ','.join(['?']*len(top_paths_list)) }) ORDER BY id DESC;"
        c.execute(sql_query, top_paths_list)
        results = c.fetchall()

        c.close()
    conn.close()

    # matplot stuff
    # Generate the figure **without using pyplot**.
    fig = Figure()
    fig.set_facecolor('#D2D4D3')
    #fig.set_figheight(6) #use autolayout instead
    ax = fig.subplots()
    ax.grid(True, color='#b2b4b3', zorder=0)
    ax.bar(top_paths_list, top_paths_counts, color=bar_color, zorder=2)
    ax.set_title(f'Top {_num_of_paths} paths', color='#111828')
    ax.set_xlabel('Path', color='#111828')
    ax.set_ylabel('Total hits', color='#111828')
    ax.set_facecolor('#D2D4D3')    

    # rotate x-axis labels for readability
    for tick in ax.get_xticklabels():
        tick.set_rotation(270)
        tick.set_fontsize(7)
        tick.set_fontfamily('monospace')
        tick.set_color('#111828')
    for tick in ax.get_yticklabels():
        tick.set_color('#111828')

    # Save it to a temporary buffer.
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plot_image = base64.b64encode(buf.getbuffer()).decode("ascii")

    return render_template('stats.html',
        #stats = results,
        analys_stats = top_paths,
        analys_titles = ['Path', 'Count'],
        totalHits = len(results),
        statName = f'Top {_num_of_paths} most common paths',
        image_data = plot_image,
        )

@analysis.route('/analysis/ip/topten', methods = ['GET'])
@login_required
def top_ips():
    """ Return most common IPs + counts. """
    _num_of_ips = int(request.args.get('limit', 36)) # num of ips to include, i.e. Top X. default 36

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT remoteaddr, COUNT(*) AS count FROM bots GROUP BY remoteaddr ORDER BY count DESC LIMIT ?;"
        # get the 10 most common remoteaddr values
        data_tuple = (_num_of_ips,)
        c.execute(sql_query, data_tuple)
        top_ips = c.fetchall()

        top_ips_list = [row['remoteaddr'] for row in top_ips]
        top_ips_counts = [row['count'] for row in top_ips]
        #logging.debug(f'Top IPs: {top_ips_list}') #testing
        #logging.debug(f'Top IPs counts: {top_ips_counts}')

        #select all rows where remoteaddr is a top10 one
        sql_query = f"SELECT * FROM bots WHERE remoteaddr IN ({ ','.join(['?']*len(top_ips_list)) }) ORDER BY id DESC;"
        c.execute(sql_query, top_ips_list)
        results = c.fetchall()

        c.close()
    conn.close()

    # matplot stuff
    # Generate the figure **without using pyplot**.
    fig = Figure()
    ax = fig.subplots()
    ax.grid(True, zorder=0)
    ax.bar(top_ips_list, top_ips_counts, color=bar_color, zorder=2)
    ax.set_title(f'Top {_num_of_ips} IPs', color='#111828')
    ax.set_xlabel('IP address', color='#111828')
    ax.set_ylabel('Total hits', color='#111828')  

    # rotate x-axis labels for readability
    for tick in ax.get_xticklabels():
        tick.set_rotation(270)
        tick.set_fontsize(8)
        #tick.set_fontfamily('Noto Sans')
        tick.set_color('#111828')
    for tick in ax.get_yticklabels():
        tick.set_color('#111828')

    # Save it to a temporary buffer.
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plot_image = base64.b64encode(buf.getbuffer()).decode("ascii")

    return render_template('stats.html',
        #stats = results,
        analys_stats = top_ips,
        analys_titles = ['IP', 'Count'],
        totalHits = len(results),
        statName = f'Top {_num_of_ips} most common IPs',
        image_data = plot_image,
        )

@analysis.route('/analysis/ua/topten', methods = ['GET'])
@login_required
def top_uas():
    """ Return most common UAs + counts. """
    num_ua = int(request.args.get('limit', 25)) # num of UAs to include, i.e. Top X. default 25

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT useragent, COUNT(*) AS count FROM bots GROUP BY useragent ORDER BY count DESC LIMIT ?;"
        # get the most common user agent values
        data_tuple = (num_ua,)
        c.execute(sql_query, data_tuple)
        top_uas = c.fetchall()

        top_uas_list = [row['useragent'] for row in top_uas]
        top_uas_counts = [row['count'] for row in top_uas]
        #logging.debug(f'Top IPs: {top_uas_list}') #testing
        #logging.debug(f'Top IPs counts: {top_uas_counts}')

        #select all rows where useragent is in top_uas_list
        sql_query = f"SELECT * FROM bots WHERE useragent IN ({ ','.join(['?']*len(top_uas_list)) }) ORDER BY id DESC;"
        c.execute(sql_query, top_uas_list)
        results = c.fetchall()

        c.close()
    conn.close()

    #Edit '' item to 'None' for display on the plot
    for i in range(len(top_uas_list)):
        if top_uas_list[i] == '':
            top_uas_list[i] = 'None'

    # matplot stuff
    # Generate the figure **without using pyplot**.
    fig = Figure()
    ax = fig.subplots()
    ax.grid(True, zorder=0)
    ax.bar(top_uas_list, top_uas_counts, color=bar_color, zorder=2)
    ax.set_title(f'Top {num_ua} User-Agents',)
    ax.set_xlabel('User-Agent', color='#111828')
    ax.set_ylabel('Total hits', color='#111828')  

    # rotate x-axis labels for readability
    for tick in ax.get_xticklabels():
        tick.set_rotation(270)
        tick.set_fontsize(6)
        #tick.set_color('#111828')
    #for tick in ax.get_yticklabels():
        #tick.set_color('#111828')

    # Save it to a temporary buffer.
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plot_image = base64.b64encode(buf.getbuffer()).decode("ascii")

    return render_template('stats.html',
        #stats = results,
        analys_stats = top_uas,
        analys_titles = ['User-Agent', 'Count'],
        totalHits = len(results),
        statName = f'Top {num_ua} User-Agents',
        image_data = plot_image,
        )

@analysis.route('/analysis/ct/topten', methods = ['GET'])
@login_required
def top_cts():
    """ Return most common UAs + counts. """
    num_ct = int(request.args.get('limit', 20)) # num of UAs to include, i.e. Top X. default 25

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT contenttype, COUNT(*) AS count FROM bots GROUP BY contenttype ORDER BY count DESC LIMIT ?;"
        # get the most common user agent values
        data_tuple = (num_ct,)
        c.execute(sql_query, data_tuple)
        top_cts = c.fetchall()

        top_cts_list = [row['contenttype'] for row in top_cts]
        top_cts_counts = [row['count'] for row in top_cts]
        #logging.debug(f'Top IPs: {top_cts_list}') #testing
        #logging.debug(f'Top IPs counts: {top_cts_counts}')

        '''
        #select all rows where content-type is in top_cts_list
        sql_query = f"SELECT * FROM bots WHERE contenttype IN ({ ','.join(['?']*len(top_cts_list)) }) ORDER BY id DESC;"
        c.execute(sql_query, top_cts_list)
        results = c.fetchall()
        '''

        c.close()
    conn.close()

    '''
    #Edit '' item to 'None' for display on the plot
    for i in range(len(top_cts_list)):
        if top_cts_list[i] == '':
            top_cts_list[i] = 'None'
    '''
    # Delete the 'none' item from top_cts_list so it's not plotted on image (makes the above redundant).
    for i in range(len(top_cts_list)):
        if top_cts_list[i] == '':
            del(top_cts_list[i])
            del(top_cts_counts[i])
            break

    '''
    # Delete '' item from top_cts (no longer needed, but leaving this here.)
    # Can use this to replace top_cts, if you don't want the blank Content-Type in the table.
    list_dictrows = [dict(row) for row in top_cts]
    list_dictrows = [d for d in list_dictrows if d.get('contenttype') != '']
    ct_list_of_tuples = [tuple(d.values()) for d in list_dictrows]
    '''

    # matplot stuff
    # Generate the figure **without using pyplot**.
    fig = Figure()
    ax = fig.subplots()
    ax.grid(True, zorder=0)
    ax.bar(top_cts_list, top_cts_counts, color=bar_color, zorder=2)
    ax.set_title(f'Top {num_ct} Content-type',)
    ax.set_xlabel('Content-type', color='#111828')
    ax.set_ylabel('Total hits', color='#111828')  

    # rotate x-axis labels for readability
    for tick in ax.get_xticklabels():
        tick.set_rotation(270)
        tick.set_fontsize(6)

    # Save it to a temporary buffer.
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plot_image = base64.b64encode(buf.getbuffer()).decode("ascii")

    return render_template('stats.html',
        #stats = results,
        analys_stats = top_cts,
        analys_titles = ['Content-type', 'Count'],
        #totalHits = len(results),
        statName = f'Top {num_ct} Content-type',
        image_data = plot_image,
        )

### For AJAX/fetch requests, to display top IP stats on stats.html

#SQLite callback for custom function
def compare_time_b(timestamp, num_days):
    """True if timestamp is within the past <num_days> days. """
    current_time = datetime.datetime.now(datetime.timezone.utc)
    cutoff = current_time - datetime.timedelta(days=num_days)
    timestamp_p = parse(timestamp).astimezone(datetime.timezone.utc)
    return timestamp_p > cutoff

@analysis.route('/analysis/api/tops/<int:days>', methods = ['GET'])
@login_required
@cache.cached(query_string=True, timeout=600)
def fetch_tops_ndays(days: int) -> dict:
    """ Return top IPs past $n days. Fetched by Javascript function for div#tops on stats.html. """

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        conn.create_function("COMPARETIME", 2, compare_time_b)

        #Get top IP of past 24 hours
        sql_query = """
            SELECT remoteaddr, COUNT(*) AS count
            FROM bots
            WHERE COMPARETIME(time, ?)
            GROUP BY remoteaddr
            ORDER BY count DESC, MAX(id) DESC
            LIMIT 1;
            """
        data_tuple = (days,)
        c.execute(sql_query, data_tuple)
        top_ip = dict(c.fetchone())

        c.close()
    conn.close()

    return top_ip

@analysis.route('/analysis/api/tops', methods = ['GET'])
@login_required
@cache.cached(query_string=True, timeout=600)
def fetch_tops_mult() -> dict:
    """ Return top IPs of past day+week+month. """

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        conn.create_function("COMPARETIME", 2, compare_time_b)

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
        top_ip_daily = dict(c.fetchone())

        #Get most common IP of past 7 days
        sql_query = """
            SELECT remoteaddr, COUNT(*) AS count
            FROM bots
            WHERE COMPARETIME(time, 7)
            GROUP BY remoteaddr
            ORDER BY count DESC, MAX(id) DESC
            LIMIT 1;
            """
        c.execute(sql_query)
        top_ip_weekly = dict(c.fetchone())

        #Get most common IP of past 30 days
        sql_query = """
            SELECT remoteaddr, COUNT(*) AS count
            FROM bots
            WHERE COMPARETIME(time, 31)
            GROUP BY remoteaddr
            ORDER BY count DESC, MAX(id) DESC
            LIMIT 1;
            """
        c.execute(sql_query)
        top_ip_monthly = dict(c.fetchone())

        c.close()
    conn.close()

    return {'day': top_ip_daily, 'week': top_ip_weekly, 'month': top_ip_monthly}
