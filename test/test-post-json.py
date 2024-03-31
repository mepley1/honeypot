#!/usr/bin/env python3
import requests

url = 'http://localhost:5000/test/post/json'
data = {
    'key 1': 'value 1',
    'key 2': 'value 2',
    }
x = requests.post(url, json = data)
print(x.status_code)
