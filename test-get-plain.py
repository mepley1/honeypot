#!/usr/bin/env python3
""" Makes a plain GET request to / with no query. """

import requests

url = 'http://localhost:5000/test/get'

headers = {
    'User-Agent': 'testing',
}

if __name__ == '__main__':
    x = requests.get(url = url, headers = headers)
    print(x.status_code)
