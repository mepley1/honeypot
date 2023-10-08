#!/usr/bin/env python3
import requests
import random
import string

url = 'http://localhost:5000/'

def get_random_string(length):
    #letters = string.ascii_letters + string.punctuation + string.digits + string.punctuation + string.whitespace
    letters = string.printable
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

#characters = string.ascii_letters + string.digits + string.punctuation
#bad_data = ''.join(random.choice(characters) for i in range(16))

bad_data = get_random_string(16)
'''
myobj = {
    "bad data": bad_data
    }
'''
myobj = bad_data
headers = {'Content-Type': 'application/json'}

x = requests.post(url, data = myobj, headers = headers)

# Print response
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
