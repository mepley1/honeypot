#!/usr/bin/env python3
import requests
import sys

if len(sys.argv) == 2:
    myobj = {sys.argv[1]:sys.argv[1]}
    myobj_string = sys.argv[1].encode(errors='replace')
elif len(sys.argv) > 2:
    myobj = {sys.argv[1]:sys.argv[2]}
    myobj_string = sys.argv[1].encode(errors='replace')
else:
    myobj = {'key 1': 'value 1', 'key 2': 'value 2'}
    myobj_string = 'lorem ipsum'

url = 'http://localhost:5000/test/post/form'
headers = {
    'User-Agent': myobj_string,
}

data2 = {
    'Key-1': 'value 1',
    'Key 2': 'value 2',
    'Key 3': 'value 3',
}

data3 = [("key1", "value1"), ("key2", "value2")]

x = requests.post(url, data = data2, headers = headers)

print(x.status_code)
#print(x.cookies)
#print(x.elapsed)
