#!/usr/bin/env python3
import requests

url = 'http://localhost:5000/test/post/form'
data = {
    'key 1': 'value 1',
    'key 2': 'value 2',
    }
data2 = {
    '0x[]': 'androxgh0st'
}
x = requests.post(url, data = data2)
print(x.status_code)
