""" Shared helper functions. """

import datetime
import sqlite3
import requests #for AbuseIPDB reporting
import json
import logging
from flask import request, current_app
from urllib.parse import urlencode #encode ip when reporting

def get_ip():
    """ Get client's IP from behind Nginx. """
    if 'X-Real-Ip' in request.headers:
        clientIP = request.headers.get('X-Real-Ip') #get real ip from behind Nginx
    else:
        clientIP = request.remote_addr
    return clientIP

def insert_login_record(username, password):
    """ sql insert helper function, for logging auth attempts. """

    if 'X-Real-Ip' in request.headers:
        clientIP = request.headers.get('X-Real-Ip') #get real ip from behind Nginx
    else:
        clientIP = request.remote_addr
    loginTime = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    #make the sqlite insert
    try:
        conn = sqlite3.connect('bots.db')
        c = conn.cursor()
        sqlQuery = """
            INSERT INTO logins
            (id,remoteaddr,username,password,time)
            VALUES (NULL, ?, ?, ?, ?);
            """
        dataTuple = (clientIP, username, password, loginTime)
        c.execute(sqlQuery, dataTuple)
        conn.commit()
    except sqlite3.Error as e:
        print(f'Error inserting login record: {e}')
    finally:
        conn.close()

def get_post_body(request):
    # Get the POSTed data
    if request.method == 'POST':
        try:
            clientPostJson = request.json
            posted_data = json.dumps(clientPostJson)
        # If not valid JSON, that will fail, so try again as request.data in case it's XML etc
        except:
            try:
                bad_data = request.data
                posted_data = bad_data
            except Exception as e:
                posted_data = str(e) # So I can see if anything is still failing
    else:
        posted_data = '' #If not a POST request, use blank
    return posted_data

#rewriting this from main blueprint
# Take a dict of the data as arg, instead of each one individually
def insert_request_data(clientIP, clientHostname, clientUserAgent, reqMethod, clientQuery, clientTime, posted_data, clientHeaders, reqUrl, reported):
    sql_query = """
        INSERT INTO bots
        (remoteaddr, hostname, useragent, requestmethod, querystring, time, postjson, headers, url, reported)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
    data_dict = {
        'remoteaddr': clientIP,
        'hostname': clientHostname,
        'useragent': clientUserAgent,
        'requestmethod':reqMethod,
        'querystring': clientQuery,
        'time': clientTime,
        'postjson': posted_data,
        'headers': str(clientHeaders),
        'url': reqUrl,
        'reported': reported
        }
    
    with sqlite3.connect('bots.db') as conn:
        cursor = conn.cursor()
        cursor.execute(sql_query, data_dict)
        conn.commit()

# Note: Move everything reporting-related to a separate reporting module
def report_all_post():
    """ Report any POST requests, and set value of reported to 1 or 0 """
    if request.method == 'POST':
        logging.info('Reporting POST request to AbuseIPDB...')
        api_url = 'https://api.abuseipdb.com/api/v2/report'
        comment = f'Honeypot detected attack: <{request.method} {request.path}>'
        params = {
            'ip': get_ip(),
            'categories': '21',
            'comment': comment,
            'timestamp':datetime.datetime.now().astimezone().replace(microsecond=0).isoformat(), #https://stackoverflow.com/questions/2150739/iso-time-iso-8601-in-python
            }
        headers = {
            'Accept': 'application/json',
            'Key': current_app.config["ABUSEIPDB"],
            }
        response = requests.post(url = api_url, headers = headers, params = params)
        decodedResponse = json.loads(response.text)
        #logging.debug(json.dumps(decodedResponse, sort_keys=True, indent=4))
        if 'errors' in decodedResponse:
            for error in decodedResponse['errors']:
                logging.error(error['detail'])
            #logging.error(error['detail'] for error in decodedResponse['errors'] if 'detail' in error)
            reported = 0
        else:
            logging.info('Success.')
            reported = 1
        return reported
    else:
        reported = 0
        return reported
