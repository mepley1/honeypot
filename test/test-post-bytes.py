#!/usr/bin/env python3
""" Testing script, just POSTs some random data to the endpoint """

import requests
import random
import string

url = 'http://localhost:5000/testing/post?bad_bytes_test'

def get_random_string(length):
    #letters = string.ascii_letters + string.punctuation + string.digits + string.punctuation + string.whitespace
    letters = string.printable
    result_str = ''.join(random.choice(letters) for i in range(length))
    return result_str

bad_data = b'\xc8\xc9\xf5'
#bad_data = b'\x21\x31\x28'

headers = {
            #'Content-Type': 'application/json',
            'Content-Type': 'application/x-www-form-urlencoded',
}

#x = requests.post(url, data = bad_data, headers = headers)
x = requests.post(url = url, data = bad_data, headers = headers)

# Print response
print(x.status_code)
