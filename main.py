"""
    Scan file, using .yara file

    @GuruTeam

"""

import optparse
import sys
import os
import subprocess
import yara
import MySQLdb
import base64
from config.general import *

# CHANGE ON DEMAND


KBOLD = '\033[1m'
KRED = '\x1B[31m'
KCYAN = '\x1B[36m'
KGREEN = '\x1B[32m'
KYELLOW = '\x1B[33m'
KNORM = '\033[0m'

_shells = []
_dfuncs = []
_urllist = []

# This list for mtime analysis
all_files = []
mtime_list = {}


def bold(text):
    return KBOLD + text + KNORM


def cyan(text):
    return KCYAN + text + KNORM


def green(text):
    return KGREEN + text + KNORM


def red(text):
    return KRED + text + KNORM


def yellow(text):
    return KYELLOW + text + KNORM


def nocolor(text):
    return text


def hide(filename): 
    if not 'userFiles' in filename:
        return filename
    return filename.split('userFiles')[1]


def gateway():
    parser = optparse.OptionParser()
    parser.add_option('--directory',    '-d', type="string", help="specify directory to scan")
    parser.add_option('--filename',     '-f', type="string", help="specify file to scan")
    parser.add_option('--outfile',      '-o', default="output.txt", type="string", help="specify outfile to write result using JSON")
    parser.add_option('--patterndb',    '-p', default=PATTERNDB, type="string", help="specify patterndb file")
    parser.add_option('--quite',        '-q', default=False, action="store_true", help="enable quite mode")
    parser.add_option('--dispm',        '-n', default=False, action="store_true", help="disable patterm matching module")
    parser.add_option('--dista',        '-t', default=False, action="store_true", help="disable taint analysis module")
    parser.add_option('--dismtime',     '-m', default=False, action="store_true", help="disable mtime analysis module")
    projectid = None

    (options, args) = parser.parse_args()

    if len(sys.argv) == 1:        
        parser.print_help()
        exit()

    return options, args, options.quite


def line_reduce(linecontent):
    if len(linecontent) > MAXLINESIZE:
        return linecontent[:MAXLINESIZE] + "..."
    else:
        return linecontent


def check_php_lib():
    try:
        process = subprocess.Popen(['php', '-v'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = process.communicate()
    except Exception, e:
        print e
        return False

    if "PHP " in stdout[:10]:
        return True
    else:
        return False


def import_shell(url, shellname, filename, filesize=0, line='?', sink='????'):
    _urllist.append(url)
    tshell = {
        "shellname": shellname,
        "url": url,
        "filename": filename,
        "filesize": filesize,
        "line": line,
        "sink": sink
    }
    _shells.append(tshell)


def scan_dangerous_function(content, url, filename):
    lines = content.split('\n')
    for lineno in range(0, len(lines)):
        for dfunc in dfuncs:
            if dfunc in lines[lineno]:
                print red( "[+] Found dangerous function\t: " + dfunc + " in " + hide(url) + "[" + str(lineno) + "]" )
                tfunc = {
                    "function": dfunc,
                    "url": url[61:],
                    "lineno": lineno,
                    "line": base64.b64encode(line_reduce(lines[lineno])),
                    "filename": filename,
                    "filesize": len(content)
                }
                _dfuncs.append(tfunc)
    return 0


def export_to_outfile(outfile):
    try:
        with open(outfile, "wb") as f:
            f.write(json.dumps({"webshell": _shells, "dfunc": _dfuncs}, ensure_ascii=False))
        print green("[+] Saved results to:\t" + outfile)
    except Exception, e:
        print "Error when try to save malResult to " + outfile
        raise Exception, e


def write_to_db(projectid):
    try:
        dbConnection = MySQLdb.connect(DBServer, DBUsername, DBPassword, DBname)
        cursor = dbConnection.cursor()
        query = "INSERT INTO malResult (projectID, result) VALUES (%s, %s)"
        cursor.execute(query, (projectid, json.dumps({"webshell":_shells, "dfunc":_dfuncs}, ensure_ascii=False)))
        dbConnection.commit()
        cursor.close()
        dbConnection.close()
        print green("[+] Saved results to database")
    except Exception, e:
        print "Error when try to save malResult to DB"
        raise Exception, e


def load_taint_analysis_result(projectid):

    def get_json_content():
        try:
            if projectid != None:
                outfile = "./../../userProjects/" + projectid + ".ta"
            else:
                outfile = '.taintanalysis-output.ta'
            with open(outfile, 'r') as f:
                output = f.read()
            return json.loads(output), outfile
        except:
            return None, None

#    print green('\n\n[ ----- Taint Analysis result ----- ]')

    outfile = ''

    json_content, outfile = get_json_content()

    if json_content is None:
        print "Taint Analysis: no result"
        return True            

    for key, values in json_content.iteritems():
        filename = key
        for value in values:
            treenodes = value['treenodes']
            for treenode in treenodes: 
                if len(key) > 60:
                    url = key[61+4:]                
                else:
                    url = key
                    # print green("Url: " + url)
                if not url in _urllist:                     
                    shellname = "GuruWS :: Taint Analysis :: " + treenode['title']
                    # line = treenode['value'].split('>')[1].split(':')[0]
                    line = treenode['value'].split(': ')[1]
                    filename = key.split('/')[-1]
                    filesize = 0
                    sink = treenode['name']                                   
                    import_shell(url, shellname, filename, filesize, line, sink)                    
    # print _shells

    return True


def taint_analysis(projectid, directory):    

    if not directory[0] == '/':
        directory = '../' + directory

    outFile = "../.taintanalysis-output.ta"    
    subprocess.call("truncate -s 0 {0}".format(outFile), shell=True)             # clean taint analysis outputfile
    command = r"""cd lib/ ; php taintanalysis.php {0} {1}""".format(directory, outFile)
    subprocess.call(command, shell=True)
    return 0


def load_mtime_analysis_result(projectid):
    for efile in all_files:
        mtime = int(os.path.getmtime(efile))
        if mtime_list[mtime] == 1:
            # print "Found unsafe file based on mtime", efile
            import_shell("none", "GuruWS_mtime", efile, 0, 0, "malicious mtime")
    pass


def show_result(file_count):
    shell_count = len(_shells)
    print green("\n\n[ -----  Reports  ----- ]")
    print yellow("[+] Analized\t: " + str(file_count) + " files ")
    if shell_count != 0:
        print yellow("[+] Found\t: " + str(shell_count) + " issues ")
    else:
        print yellow("[+] Great ! Nothing found, or something went wrong :)")
    
    for shell in _shells:
        print shell
        print cyan("[+] Found...\t" + shell['shellname'] + " " + "\tin (" + shell['filename'] + ")")   


def is_whitelist(filename):
    if '/.git/' in filename:
        return True
    if '/.idea/' in filename:
        return True
    return False


if __name__ == '__main__':

    if not check_php_lib():
        print "You should install php5 first"
        exit(0)

    options, args, QUITEMODE = gateway()
    projectid = None            # Disabled

    if not options.dispm:           # if Pattern Matching module has been enabled...
        print "PATTERNDB:", options.patterndb
        rules = yara.compile(options.patterndb)

    file_count = 0

    if options.filename:
        """
            For a single file
            Only perform pattern matching, Taint Analysis module is unavailable
        """

        filename = options.filename

        if not QUITEMODE:
            print cyan("[+] Scanning a single file...\t"), cyan(filename)
            
        matches = rules.match(filename)
        if matches:
            for match in matches:
                print red("[+] Found...\t"), red(str(match)), red("\tin (") + red(hide(filename)) + red(")")
        else:
            print yellow("[+] Great ! Nothing found, or something went wrong :)")

    if options.directory:
        """
            For a directory
        """

        rootDir = options.directory
        if rootDir[-1] != '/':
            rootDir += '/'

        if not options.dista:
            taint_analysis(projectid, options.directory)

        for dirName, subdirList, fileList in os.walk(rootDir):
            if dirName[-1] != '/':
                dirName += '/'

            for fname in fileList:
                filename = dirName + fname  # get absolute filename                
                file_count += 1

                if is_whitelist(filename):
                    print cyan("[+] ignored"), cyan(hide(filename))
                    continue

                if not QUITEMODE:
                    print cyan("[+] Scanning...\t"), cyan(hide(filename))

                if (not options.dismtime) and (not is_whitelist(filename)):

                    all_files.append(filename)

                    mtime = int(os.path.getmtime(filename))

                    if mtime in mtime_list:
                        mtime_list[mtime] += 1
                    else:
                        mtime_list[mtime] = 1

                if not options.dispm:
                    try:
                        with open(filename, 'rb') as f:
                            filecontent = f.read()
                    except Exception, e:
                        print "can't open", filename, e
                        continue

                    if len(filecontent) == 0:
                        continue
                    matches = rules.match(filename)
                    # url = filename[61:]
                    url = filename

                    if matches != [] and not url in _urllist:
                        print "-----"
                        # shell_count += 1
                        shellname = str(matches[0])
                        filesize = len(filecontent)
                        import_shell(url, shellname, fname, filesize)
                        # print cyan("[+] Found...\t"), red(shellname), red("\tin (") + red(hide(filename)) + red(")")
                    else:
                        scan_dangerous_function(filecontent, filename, fname)
                        # just scan dangerous function with the file, which is not be detect as shellcode

            # show_result(file_count)

        if not options.dista:
            load_taint_analysis_result(projectid)

        if not options.dismtime:
            load_mtime_analysis_result(projectid)

        show_result(file_count)

        if options.outfile:
            export_to_outfile(options.outfile)     # just export when scan directory

        if projectid:
            write_to_db(projectid)

""" JSON struct:

    {
        "dfunc":
            [{
                "function": "lolololol",
                "filename": "passwd",
                "url": "/etc/passwd",
                "lineno": 0,
                "line": 0,
                "filesize": 122
                }]
        ,
        "webshell":
            [{
                "shellname": "lololol0l",
                "url": "/bin/sh",
                "filename": "sh",
                "filesize": 11
                }]

        }


"""
