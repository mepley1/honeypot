#!/usr/bin/env python3
# Test detection of hikvision command injection exploit attempts

import requests

url = 'http://localhost:5000/SDK/webLanguage'
data = """<?xml version="1.0" encoding="UTF-8"?>
                                            <language>$(ping -c 1 127.0.0.1)</language>"""
headers = {'content-type': 'application/x-www-form-urlencoded; charset=UTF-8'}
x = requests.put(url, data = data, headers = headers)
print(x.status_code)
