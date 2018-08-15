# PunWSD
Pun Web Shell Detector

## Key Features
* Detect WebShell and dangerous functions

## Requirements:
* packages
`php`,
[`yara`](http://yara.readthedocs.io/en/v3.4.0/gettingstarted.html)

* python lib
`yara`


## Usage:
```
$ python2 main.py                                 
Usage: main.py [options]

Options:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory=DIRECTORY
                        specify directory to scan
  -f FILENAME, --filename=FILENAME
                        specify file to scan
  -o OUTFILE, --outfile=OUTFILE
                        specify outfile to write result using JSON
  -p PATTERNDB, --patterndb=PATTERNDB
                        specify patterndb file
                        default value: config/final.yara
  -q, --quite           enable quite mode

$ python2 main.py -d ../../userFiles/5fd8f263781c4b6dbfb6f14878be34bc3fb7c0df/
[+] Scanning...  /5fd8f263781c4b6dbfb6f14878be34bc3fb7c0df//shell.php
[+] Found...   SHELL_SHELLDETECT_spam_2__0__php   in (/5fd8f263781c4b6dbfb6f14878be34bc3fb7c0df//shell.php)
[+] Analized  : 1 files 
[+] Found : 1 shells 

```

## Development

### Build your own signatures DB

```
$ cd lib/
$ python2 pm_patterns_export.py -d ../data/all/ -o ../config/final.yara
```

Then, the created signature has been stored at `config/final.yara`.

## Changelog
* Not yet released

## Thanks to:
* https://github.com/tennc/webshell
* https://github.com/emposha/PHP-Shell-Detector
* https://github.com/robocoder/rips-scanner


