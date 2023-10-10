""" Shared helper functions. """

import datetime
import sqlite3
from flask import request

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
