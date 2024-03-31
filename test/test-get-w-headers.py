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
    'host': 'example.com',
    'test-1': myobj1,
    'test-2': myobj2,
    'test-bytes': b'\xa8\xc8\xa9\xff',
    'test-header-inject': "};print('test');quit();",
    't5': "<img src='aaa' onerror=alert(1)>",
}

if __name__ == '__main__':
    x = requests.get(url = url, headers = headers)
    print(x.status_code)
