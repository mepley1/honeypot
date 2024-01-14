#!/usr/bin/env python3
""" Make a GET request with some headers to test detections of proxy headers + smuggling. """

import requests
import sys

if len(sys.argv) == 2:
    myobj1 = sys.argv[1]
    myobj2 = sys.argv[1]
elif len(sys.argv) > 2:
    myobj1 = sys.argv[1]
    myobj2 = sys.argv[2]
else:
    myobj1 = 'key 1'
    myobj2 = 'value 1'

url = 'http://localhost:5000/test/get/headers'

headers = {
    'User-Agent': 'test',
    #'Proxy-Connection': 'keep-alive', #Proxy header detection
    #'proxy-authorization': 'test',
    'host': 'example.com:80', #request smuggling
    'test1': myobj1,
    'test2': myobj2,
}

if __name__ == '__main__':
    x = requests.get(url = url, headers = headers)
    print(x.status_code)
