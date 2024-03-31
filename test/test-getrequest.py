#!/usr/bin/env python3
import requests
url = 'http://localhost:5000/test/get'
params = {
    "query1":"value1",
    "query2":"value2",
}
headers = {
    "User-Agent":"<script>javascript:alert(1)</script>",
}

if __name__ == '__main__':
    x = requests.get(url = url, params = params, headers = headers)
    print(x.status_code)
