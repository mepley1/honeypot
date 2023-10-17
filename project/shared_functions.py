""" Shared helper functions. """

import datetime
import sqlite3
import requests #for AbuseIPDB reporting
import json
from flask import request, current_app

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

def get_post_body():
    # Get the POSTed data
    if reqMethod == 'POST':
        try:
            clientPostJson = request.json
            postData = json.dumps(clientPostJson)
        # If not valid JSON, that will fail, so try again as request.data in case it's XML etc
        except:
            try:
                badData = request.data
                postData = badData
            except Exception as e:
                postData = str(e) # So I can see if anything is still failing
    else:
        postData = '' #If not a POST request, use blank

def report_all_post():
    """ Report any POST requests, and set value of reported to 1 or 0 """
    if request.method == 'POST':
        print('Reporting POST request to AbuseIPDB...')
        api_url = 'https://api.abuseipdb.com/api/v2/report'
        comment = f'Honeypot detected attack: <{request.method} http://[redacted]{request.path}>'

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
        #print(json.dumps(decodedResponse, sort_keys=True, indent=4))
        if 'errors' in decodedResponse:
            print('Error while reporting.')
            reported = 0
        else:
            print('Success.')
            reported = 1
        return reported
    else:
        reported = 0
        return reported

# Make a report button on stats page too. Like a form, pull the row[whatever] values and pass to a /report route or something.
# /report route can go in its own blueprint file with other reporting shit