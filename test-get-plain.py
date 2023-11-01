#!/usr/bin/env python3
""" Makes a plain GET request to /. """

import requests

url = 'http://localhost:5000'

headers = {
    'User-Agent': '',
}

if __name__ == '__main__':
    x = requests.get(url = url, headers = headers)
    print(x.status_code)
