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

headers = {
    'user-agent': bad_data,
        }

x = requests.post(url = url, data = bad_data, headers = headers)

print(x.status_code)
