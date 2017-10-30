#!/usr/bin/python 2.7
# configuration file

import json

# Display
QUITEMODE = False

# Pattern
PATTERNDB = 'config/final.yara'

# dangeous function
dfuncs = ["preg_replace", "passthru", "shell_exec", "exec", "base64_decode", "eval", "system", "proc_open", "popen",
          "curl_exec", "curl_multi_exec", "parse_ini_file", "show_source"]

MAXLINESIZE = 200