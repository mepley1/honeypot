#!/usr/bin/env python3

import requests
url = 'http://localhost:5000/test/post'
data = '1'
x = requests.post(url = url, data = data)
print(x.status_code)
