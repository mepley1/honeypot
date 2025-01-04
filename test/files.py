#!/usr/bin/env python3
# Send files in request

import requests

url = 'http://localhost:5000/test/post-files'

files = {'file': open('./image.png' ,'rb')}

x = requests.post(url, files=files)
print(x.status_code)
