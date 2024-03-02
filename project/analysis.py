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

analysis = Blueprint('analysis', __name__)
requests_db = 'bots.db'
set_pyplot_loglevel(level = 'warning') #shut up matplotlib

#Set autolayout for matplotlib plots
from matplotlib import rcParams
rcParams.update({'figure.autolayout': True})

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

    # Save it to a temporary buffer.
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plot_image = base64.b64encode(buf.getbuffer()).decode("ascii")

    return render_template('stats.html',
        statName = f'Total hits by date',
        subtitle = f'{date_labels[0]} - {date_labels[-1]}',
        image_data = plot_image,
        )

@analysis.route('/stats/ip/per_day')
@login_required
def ip_per_day():
    """ Return total # of hits per day. """
    #List of hosts() in ipaddress.ip_network: https://docs.python.org/3/howto/ipaddress.html
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

    daily_avg = sum(hits_per_day) / num_of_days

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
    ax.grid(True)

    # rotate x-axis labels for readability
    for tick in ax.get_xticklabels():
        tick.set_rotation(90)
        tick.set_fontsize(8)
        #tick.set_fontfamily('Hack')

    # Save it to a temporary buffer.
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plot_image = base64.b64encode(buf.getbuffer()).decode("ascii")

    flash(f'Daily avg: {daily_avg}', 'info')
    return render_template('stats.html',
        statName = f'Total hits by date',
        subtitle = f'IP: {ip}',
        image_data = plot_image,
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

        # Now query for all requests received from top_ips
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
        statName = f'Top {_num_of_urls} most common URLs'
        )

@analysis.route('/analysis/path/topten', methods = ['GET'])
@login_required
def top_ten_paths():
    """ Return top ten most common paths. """
    _num_of_paths = request.args.get('limit', 10) # num of paths to include, i.e. Top X paths. default 10

    '''if not isinstance(_num_of_paths, int):
        flash('Bad request: `limit` must be type int', 'error')
        return render_template('index.html')'''

    with sqlite3.connect(requests_db) as conn:
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        sql_query = "SELECT path, COUNT(*) AS count FROM bots GROUP BY path ORDER BY count DESC LIMIT ?;"
        # Execute the SQL query to get the 10 most common remoteaddr values
        data_tuple = (_num_of_paths,)
        c.execute(sql_query, data_tuple)
        top_paths = c.fetchall()

        top_paths_list = [row['path'] for row in top_paths]
        top_paths_counts = [row['count'] for row in top_paths]

        logging.debug(f'Top paths: {top_paths_list}') #testing, delete this
        logging.debug(f'Top path counts: {top_paths_counts}')

        #delete the None from the list (database rows where there's no data, before I started saving paths)
        for i in reversed(range(len(top_paths_list))):
            if top_paths_list[i] is None:
                del top_paths_list[i]
                del top_paths_counts[i]

        sql_query = f"SELECT * FROM bots WHERE path IN ({ ','.join(['?']*len(top_paths_list)) }) ORDER BY id DESC;"
        c.execute(sql_query, top_paths_list)
        results = c.fetchall()

        c.close()
    conn.close()

    # matplot shit
    # Generate the figure **without using pyplot**.
    fig = Figure()
    #fig.set_figheight(8)
    ax = fig.subplots()
    #fig.subplots_adjust(bottom=0.35)
    ax.bar(top_paths_list, top_paths_counts)
    ax.set_title(f'Top {_num_of_paths} paths')
    ax.set_xlabel('Path')
    ax.set_ylabel('Total hits')

    #ax.set_ylim(0, 500) #limit y-axis to soften outliers
    ax.grid(True)

    # rotate x-axis labels for readability
    for tick in ax.get_xticklabels():
        tick.set_rotation(270)
        tick.set_fontsize(7)
        #tick.set_fontfamily('Hack')

    # Save it to a temporary buffer.
    buf = BytesIO()
    fig.savefig(buf, format="png")
    plot_image = base64.b64encode(buf.getbuffer()).decode("ascii")



    # Print the results
    for row in top_paths:
        flash(f'path: {row["path"]}, Count: {row["count"]}', 'info')
    return render_template('stats.html',
        #stats = results,
        totalHits = len(results),
        statName = f'Top {_num_of_paths} most common paths',
        image_data = plot_image,
        )
