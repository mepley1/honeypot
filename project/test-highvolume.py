#!/usr/bin/env python3

import requests
import threading

# Testing high volume of requests

url = 'http://localhost:5000'

def getRequest(num_of_requests):
    for i in range(0, num_of_requests):
        x = requests.get(url)
        print(x.status_code, '\n')
    print('thread finished \n')

def postRequest(num_of_requests):
    for i in range(0,num_of_requests):
        myobj = {
            'key1':'from testscript',
            'key2':'value2',
        }
        x = requests.post(url, myobj)
        print(x.status_code, '\n')
    print('thread finished \n')

if __name__ == '__main__':
    t1 = threading.Thread(target = getRequest, args=(64,))
    t2 = threading.Thread(target = postRequest, args=(64,))
    t3 = threading.Thread(target = getRequest, args=(64,))
    
    t1.start()
    t2.start()
    t3.start()

    t1.join()
    t2.join()
    t3.join()

    print('DONE')
