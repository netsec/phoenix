#!/usr/bin/python
## This only works for RL right now, VT polling will be added shortly
import requests, json, os.path, random, logging, hashlib
from datetime import date, timedelta, datetime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
now = date.today()
rnow = datetime.now()
yesterday = date.today() - timedelta(1)
yest = yesterday.strftime('%Y-%m-%d')
today = now.strftime('%Y-%m-%d')
mytime = rnow.strftime('%Y-%m-%d %H:%M:%s')
storagedir = "/data/malicious_files"
token = ''
owner = 'phoenix@phoenix.beastmode.tools'
import os, random, requests


def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def submit2cuckoo(myfile, vpn, ftype):
    logger.info(mytime + ' submitting : ' + myfile)
    url = "http://127.0.0.1:8090/tasks/create/file"
    files = dict(
        file=open(myfile, "rb"),
        filename=os.path.basename(myfile)
    )
    vpns = ["AUMelbourne", "AUSydney", "Brazil", "CAMontreal", "CAToronto", "Denmark", "Finland", "France", "HongKong",
            "India", "Israel", "Italy", "Japan", "Mexico", "Netherlands", "NewZealand", "Norway", "Romania",
            "Singapore", "Sweden", "Switzerland", "Turkey", "UKLondon", "UKSouthampton", "USCalifornia", "USChicago",
            "USEast", "USFlorida", "USMidwest", "USNewYorkCity", "USSeattle", "USSiliconValley", "USTexas", "USWest"]
    with open(myfile, 'rb') as sample:
        if vpn:
            data = dict(options='route=' + random.choice(vpns) + ',procmemdump=yes',
                        owner=owner, tlp='green', timeout=90, enforce_timeout=True)
        else:
            data = dict(options='procmemdump=yes', owner=owner, tlp='green', timeout=30,
                        enforce_timeout=True)
        if ftype:
            data['package'] = ftype
        r = requests.post(url, files=files, data=data)
        logger.debug(mytime + " " + str(r))


def dlFile(myhash, yrule, ext):
    if not os.path.exists(storagedir + '/' + yrule):
        os.makedirs(storagedir + '/' + yrule)
    if ext == "MS Word Document":
        ex = '.doc'
        ofile = storagedir + '/' + yrule + '/' + myhash + ex
    elif ext == "MS Excel Spreadsheet":
        ex = '.xls'
        ofile = storagedir + '/' + yrule + '/' + myhash + ex
    elif ext.startswith('CDF V2 Document'):
        ex = '.doc'
        ofile = storagedir + '/' + yrule + '/' + myhash + ex
    else:
        ofile = storagedir + '/' + yrule + '/' + myhash
    logger.debug(mytime + " Checking existing store for Sample " + ofile)
    for root, dirs, files in os.walk(storagedir):
        for name in files:
            if myhash in name:
                logger.debug(mytime + ' already have the file ' + myhash)
                return
    else:
        logger.info(mytime + ' downloading file ' + myhash)
        response = requests.get("https://a1000.reversinglabs.com/api/samples/" + myhash + "/download/",
                                headers={"Authorization": "Token %s" % token})
        logger.debug(mytime + " " + str(response))
        downloaded_file = response.content
        f = open(ofile, 'w')
        f.write(downloaded_file)
        f.close()
        if myhash != sha256_checksum(ofile):
            logger.error(mytime + " File downloaded doesn't match hash")
            return
        else:
            logger.debug(mytime + " Downloaded file hash matches")
        if (ext == "MS Word Docuement") or (ext == "Rich Text Format") or (ext == "MicrosoftWord:Generic"):
            submit2cuckoo(ofile, True, 'doc')
        else:
            submit2cuckoo(ofile, True, None)
        return


def getFileList():
    params = {'apikey': akey}
    response = requests.get('https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=' + akey)
    results = ""
    for r in response:
        results = results + r
    return results


def getRLFileList():
    res = requests.get("https://a1000.reversinglabs.com/api/yara/ruleset/matches/?name=word_droppers",
                       headers={"Authorization": "Token %s" % token})
    hits = json.loads(res.content)
    return hits["results"]


myf = getRLFileList()
if myf:
    hcount = len(myf)
    logger.info(mytime + ' Going through ' + str(hcount) + ' files from ReversingLabs')
    for h in myf:
        yrule = h['rule']
        myhash = h['sha256']
        ext = h['file_type']
        s = h['file_size']
        ruleset = h['rule']
        logger.debug(mytime + ' - ' + ruleset + ' - ' + yrule + ' - ' + myhash)
        if (s < 7168):
            logger.info(mytime + ' File too small, not going further')
        elif myhash == 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855':
            logger.info(mytime + ' File is empty for some reason')
        else:
            if ruleset:
                dlFile(myhash, yrule, ext)
