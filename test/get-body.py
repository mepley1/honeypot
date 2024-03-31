#!/usr/bin/env python3
import requests
url = 'http://localhost:5000/test/get/with-body'
data = {
    "query1":"value1",
    "query2":"value2",
}
data_b = '1234'
#bad_data = b'ByteObject'
bad_data = b'\xc8\xc9\xf5'
headers = {
    "User-Agent": "1",
    "Content-Type": "application/x-www-form-urlencoded",
}

if __name__ == '__main__':
    x = requests.get(url = url, data=data, headers = headers)
    print(x.status_code)
