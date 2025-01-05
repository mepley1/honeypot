#!/usr/bin/env python3
# Test detection of Netgear DGN command injection

import requests

url = 'http://localhost:5000/setup.cgi?next_file=netgear.cfg&todo=syscmd&cmd=cat+/www/.htpasswd&curpath=/&currentsetting.htm=1'
url_short = 'http://localhost:5000/setup.cgi?currentsetting.htm=1'

# Both requests should be reported.
x = requests.get(url)
y = requests.get(url_short)
print(x.status_code)
print(y.status_code)
