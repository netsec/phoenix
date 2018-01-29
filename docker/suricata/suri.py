#!/usr/bin/python
import glob
import json
import os
import sys
import time
from datetime import datetime
from shutil import copyfile

from elasticsearch import Elasticsearch
from elasticsearch.helpers import bulk
from suricatasc import *

SOCKET_PATH = "/var/run/suricata/suricata-command.socket"
sc = SuricataSC(SOCKET_PATH, verbose='')


def progress(count, total, status):
    bar_len = 60
    filled_len = int(round(bar_len * count / float(total)))
    percents = round(100.0 * count / float(total), 1)
    bar = '=' * filled_len + '-' * (bar_len - filled_len)
    print '[%s] %s%s ...%s\r' % (bar, percents, '%', status)


def connectToSuri(cmd):
    if cmd == "close":
        sc.close()
    if cmd == "open":
        try:
            sc.connect()
        except SuricataNetException as err:
            print("Unable to connect to socket %s: %s" % (SOCKET_PATH, err), sys.stderr)
            sys.exit(1)
        except SuricataReturnException as err:
            print("Unable to negotiate version with server: %s" % (err), sys.stderr)
            sys.exit(1)


def backgroundSuri(conf, rules, suri, hdir):
    d = "/var/run/suricata"
    copyfile(conf, '/etc/suricata/suricata.yaml')
    if not os.path.exists(d):
        os.makedirs(d)
    os.system(
        suri + " -vvvv -k none -c /app/suricata.yaml -S " + rules + " --unix-socket 2>&1 | tee " + hdir + "/suricata.log &")


def getFiles(ifile):
    with open(ifile) as f:
        flist = f.read().splitlines()
    return flist


def addToSuri(fileList, hdir):
    for file in fileList:
        if os.path.isfile(file):
            odir = str(hdir + '/output' + file.split('/')[2])
            if not os.path.exists(odir):
                os.makedirs(odir)
            print 'doing ' + file
            (command, arguments) = sc.parse_command('pcap-file ' + file + ' ' + odir)
            res = sc.send_command(command, arguments)


def waitForSuri(ifile, myprogress):
    done = False
    while not done:
        checkResult = sc.send_command("pcap-file-number", {})
        if checkResult["message"] == 0:
            done = True
        else:
            if myprogress:
                with open(ifile) as f:
                    total = len(f.readlines())
                d = total - checkResult["message"]
                progress(d, total, ' Running Suricata against ' + str(total) + ' pcaps')
            time.sleep(2)


def suri2ES(myuuid, es_client, user, hdir, tlp):
    # gl = '/tmp/output*'
    # flist = glob.glob(gl)
    flist = glob.glob(hdir + "/output*/eve.json")
    for f in flist:
        with open(f) as j:
            lines = j.readlines()
        docs = []
        mon = datetime.now().strftime('%Y%m%d')
        for line in lines:
            d = json.loads(line.strip())
            d['_index'] = 'hunt-' + mon
            d['_type'] = 'suricata'
            d['uuid'] = myuuid
            d['analysis_id'] = f.split('/output')[1].split('/')[0]
            d['username'] = user
            d['tlp'] = tlp
            docs.append(d)
        bulk(es_client, docs)
        # convert back to iterable and move bulk back to caller.
        # Use "yield d" instead and pass iterable into bulk

def main():
    myuuid = str(sys.argv[1])
    user = str(sys.argv[2])
    tlp = str(sys.argv[3])
    slice_num = str(sys.argv[4])
    run_in_suri(myuuid, slice_num, tlp, user)


def run_in_suri(myuuid, slice_num, tlp, user):
    hdir = "/input/.hunting/" + myuuid + "/" + slice_num
    suri = "/usr/bin/suricata"
    # suriConf="/etc/suricata/suricata-debian.yaml"
    suriConf = hdir + "/suricata.yaml"
    suriRule = hdir + "/all.rules"
    ifile = hdir + "/infiles"
    eshost = "10.200.10.20:9200"    #TODO: Put this host in config
    backgroundSuri(suriConf, suriRule, suri, hdir)
    g = getFiles(ifile)
    while not os.path.exists(SOCKET_PATH):
        time.sleep(1)
    connectToSuri("open")
    # print 'finished getting files'
    run = addToSuri(g, hdir)
    waitForSuri(ifile, True)
    connectToSuri("close")
    es = Elasticsearch(eshost)
    suri2ES(myuuid, es, user, hdir, tlp)


if __name__ == "__main__":
    main()
