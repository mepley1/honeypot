#!/usr/bin/env python3
""" Testing script, just POSTs some random data to the endpoint """

import requests
import random
import string

url = 'http://localhost:5000/testing/post?test'

def get_random_string(length):
    #letters = string.ascii_letters + string.punctuation + string.digits + string.punctuation + string.whitespace
    letters = string.printable
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

bad_data = get_random_string(16)

headers = {'Content-Type': 'application/json'}

#x = requests.post(url, data = bad_data, headers = headers)
x = requests.post(url = url, data = bad_data)

# Print response
print(x.status_code)
#print(x.text)
#print(x.content)
#print(x.encoding)
#print(x.close())
#print(x.cookies)
#print(x.is_permanent_redirect)
#print(x.elapsed)
#print(x.history)
#print(x.is_redirect)
#x.iter_content()
#x.json()
#x.url
#x.request
#x.reason
#x.raise_for_status()
#x.ok
#x.links
