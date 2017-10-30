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
    params = {'apikey': '...', 'resource': hashfile}
    headers = {
      "Accept-Encoding": "gzip, deflate",
      "User-Agent" : "gzip,  My Python requests library example client or username"
      }
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
      params=params, headers=headers)
    json_response = response.json()
    return json_response


def evaluate():
    # fn_hashs = hashs.split('\n')
    for root, dirnames, filenames in os.walk('output/'):
        for filename in filenames:
            with open('output/' + filename, "r") as f:
                d = f.read()
                d = d.replace("u'", "'")
                d = d.replace("'", "\"")
                d = d.replace('False', '"False"')
                d = d.replace('None', '"None"')
                d = d.replace('True', '"True"')
                print d
                # continue

                json_d = json.loads(d)
                
            try:
                for n, v in json_d['scans'].iteritems():
                    print n, v
                    if not n in AVs:
                        AVs[n] = 0
                    if v['detected'] == 'True':
                        AVs[n] += 1
            except Exception, e:
                print json_d
    # print len(fn_hashs)
    print AVs


if __name__ == '__main__':
    
    evaluate()



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