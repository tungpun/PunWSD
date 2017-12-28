import json

with open("output.txt", "r") as f:
    rawd = f.read()
d = json.loads(rawd)
d = d['webshell']
for e in d:
    if e['shellname'] != "SHELL_RAWLIST_Emperor":
        print e['url'][64:]
        print ">", e['shellname']
        print ""
