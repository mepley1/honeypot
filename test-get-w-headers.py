#!/usr/bin/env python3
""" Make a GET request with some headers to test detections of proxy headers + smuggling. """

import requests

url = 'http://localhost:5000/test/get/headers'

headers = {
    'User-Agent': 'test',
    'Proxy-Connection': 'keep-alive', #Proxy header detection
    'proxy-authorization': 'test',
    'host': 'localhost:80', #request smuggling
}

if __name__ == '__main__':
    x = requests.get(url = url, headers = headers)
    print(x.status_code)
