#!/usr/bin/env python3
import requests
url = 'http://localhost:5000/test/get'
params = {
    #"&^$#=-+_":":;'",
    "query1":"value1",
    "query2":"value2",
}
headers = {
    "User-Agent":"!@#$%^&*()-_=+/?<>",
}
x = requests.get(url = url, params = params, headers = headers)
print(x.status_code)
