import requests
import os
import json

AVResults = {}

def submit_filename(filename):
    params = {'apikey': 'd89e1d5abe2a9bb28e66c16256ab95efa5e614d967da7b5826337a9191810870'}
    files = {'file': (filename, open('../all/' + filename, 'rb'))}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)

    if response.status_code != 200:
        print(response.status_code)
        print(response.text)
        exit(0)

    json_response = response.json()

    print(json_response)
    with open("output_2/" + filename + ".txt", "w") as f:
        f.write(str(json_response))

def evaluate():
    cnt = 0
    for root, dirnames, filenames in os.walk('../all/'):
        for filename in sorted(filenames):
            print(filename)
            submit_filename(filename)
            pass

def read_result_file(filehash, filename):
    headers = {
      "Accept-Encoding": "gzip, deflate",
    }
    params = {'apikey': 'd89e1d5abe2a9bb28e66c16256ab95efa5e614d967da7b5826337a9191810870', 'resource': filehash}
    response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
      params=params, headers=headers)
    json_response = response.json()
    with open('av-results/{}'.format(filename), 'w') as f:
        f.write(str(json_response))

    for name, value in json_response["scans"].iteritems():
        print name, value
        if value["detected"]:
            if name in AVResults:
                AVResults[name] += 1
            else:
                AVResults[name] = 1


def read_result():
    root_dir = "output_2/"
    for dir_name, subdirlist, filenames in os.walk(root_dir):
        for filename in filenames[:1]:
            data = open('output_2/{}'.format(filename), 'r').read()
            data = data.replace("\'", "\"")
            dataj = json.loads(data)
            print filename, dataj["sha256"]
            read_result_file(dataj["sha256"], filename)

if __name__ == '__main__':
    # evaluate()
    read_result()
