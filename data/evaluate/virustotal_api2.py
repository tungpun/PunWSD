#!/usr/bin/python 2.7
"""
    $ python virustotal.py ../../data/test-fp/randomized/
"""

import requests
import os
import subprocess
import time
import json
import sys

AVs = {}
cnt = 0


def rescan():
    params = {'apikey': '...', 'resource': '...'}
    headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "gzip,  My Python requests library example client or username"
      }
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/rescan',
     params=params)
    json_response = response.json()
    print json_response


def scan(filename):
    try:
        print filename
        params = {'apikey': '...'}
        files = {'file': (filename, open(filename, 'rb'))}
        response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
        json_response = response.json()
        return json_response
    except Exception, e:
        return None


def readresp(hashfile):
    if cnt % 3 == 0:
        apikey = 'e9eff638b3d37cc793be27843d6a865ec80142f199f73e100a031abe7ee07714'
    elif cnt % 3 == 1:
        apikey = '2761c5d74248dd64244baed4d128b1e53032fe7cec7773d93dd179c40a02e0e9'
    else:
        apikey = 'e54b9dc0a45dad18875e329630fc40b107c87c20742bef9d94f414ed7abbc448'

    params = {'apikey': apikey, 'resource': hashfile}
    headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "gzip,  My Python requests library example client or username"
      }

    while True:
        try:
            response = requests.get(
                'https://www.virustotal.com/vtapi/v2/file/report',
                params=params,
                headers=headers,
                timeout=3
            )
            break
        except Exception, e:
            print e
            pass

    json_response = response.json()
    return json_response


if __name__ == '__main__':
    
    dirname = sys.argv[1]

    for root, dirnames, filenames in os.walk(dirname):
        """
        for filename in filenames:
            full_filename = dirname + filename.strip()
            resp = scan(full_filename)
#            with open('dirname52681c9364166344fb73980cf0cc565cbcdd64a6e70e848151609a5335a910c8/' + full_filename[8:] + '.txt', 'w') as f:
#                f.write(str(resp))
            print filename, "Done"
            time.sleep(15)
       """ 

        for filename in filenames:
            # print filename
            cnt += 1
            if cnt < 4160:
                continue
            print "cnt", cnt
            full_filename = dirname + filename.strip()
            resp = subprocess.check_output(['md5', full_filename]).strip()
            hashfile = resp.split(' = ')[1]
            print hashfile
            with open('output/' + hashfile + '.txt', 'w') as f:
                resp_virustotal = readresp(hashfile)
                f.write(str(resp_virustotal))
            time.sleep(5)


"""
Total: 
    Test: 616
    Train data: 2023
Result:
    grMalwrScanner 526
    WebShell Detector: 407
    other
    {u'Bkav': 126, u'TotalDefense': 54, u'MicroWorld-eScan': 219, u'nProtect': 1, u'CMC': 97, u'CAT-QuickHeal': 115, u'McAfee': 125, u'Malwarebytes': 0, u'VIPRE': 74, u'TheHacker': 18, u'Baid': 221, u'K7GW': 24, u'K7AntiVirus': 24, u'F-Prot': 95, u'Symantec': 246, u'ESET-NOD32': 235, u'TrendMicro-HouseCall': 229, u'Avast': 266, u'ClamAV': 166, u'Kaspersky': 213, u'BitDefender': 219, u'NANO-Antivirus': 218, u'ViRobot': 95, u'AegisLab': 278, u'Rising': 96, u'Ad-Aware': 217, u'Sophos': 172, u'Comodo': 217, u'F-Secure': 215, u'DrWeb': 140, u'Zillya': 8, u'TrendMicro': 195, u'McAfee-GW-Edition': 134, u'Emsisoft': 213, u'Cyren': 127, u'Jiangmin': 65, u'Webroot': 10, u'Avira': 234, u'Antiy-AVL': 27, u'Kingsoft': 4, u'Microsoft': 121, u'Arcabit': 220, u'SUPERAntiSpyware': 0, u'ZoneAlarm': 213, u'GData': 273, u'AhnLab-V3': 320, u'ALYac': 242, u'AVware': 117, u'VBA32': 142, u'Zoner': 0, u'Tencent': 239, u'Yandex': 52, u'Ikarus': 284, u'Fortinet': 169, u'AVG': 195, u'Panda': 33, u'Qihoo-360': 269}
"""