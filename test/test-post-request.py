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

url = 'http://localhost:5000/' + myobj_string.decode()
headers = {
    #'Host': myobj_string.decode('latin-1', errors='replace'),
    'User-Agent': myobj_string,
    'test-1': myobj_string,
}

x = requests.post(url, json = myobj, headers = headers)

#print(x.text)
print(x.status_code)
#print(x.content)
#print(x.encoding)
#print(x.close())
#print(x.cookies)
#print(x.is_permanent_redirect)
#print(x.elapsed)
#print(x.history)
#print(x.is_redirect)
'''
x.iter_content()
x.json()
x.url
x.request
x.reason
x.raise_for_status()
x.ok
x.links
'''
