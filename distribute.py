#!/usr/bin/python 2.7

import os

root_dir = "data/all/"
cnt = 0
for dir_name, subdirlist, filenames in os.walk(root_dir):
    for filename in filenames:
        filedir = dir_name + filename
        print(filedir)
        group = cnt % 10
        data = open(filedir, 'rb').read()
        for grp in range(0, 10):
            if grp != group:
                with open('data/10fold-buildyara/{}/{}'.format(str(grp), filename), 'w') as f:
                    f.write(data)

        cnt += 1