#!/usr/bin/python
## This only works for RL right now, VT polling will be added shortly
import requests, json, os.path, random, logging, hashlib, sys
from datetime import date, timedelta, datetime
from random import randint
sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), "..",".."))

from lib.cuckoo.core.database import Database, Sample

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
now = date.today()
rnow = datetime.now()
yesterday = date.today() - timedelta(1)
yest = yesterday.strftime('%Y-%m-%d')
today = now.strftime('%Y-%m-%d')
mytime = rnow.strftime('%Y-%m-%d %H:%M:%s')
storagedir = "/data/malicious_files"
token = 'A1000_API_KEY'
owner = 'SUBMITTING_USER_EMAIL'
import os, random, requests, pymongo
mongo = pymongo.MongoClient("172.18.1.254", 27017)["cuckoo"]
db = Database()

def sha1_checksum(filename, block_size=65536):
    sha1 = hashlib.sha1()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha1.update(block)
    return sha1.hexdigest()

def sha256_checksum(filename, block_size=65536):
    sha256 = hashlib.sha256()
    with open(filename, 'rb') as f:
        for block in iter(lambda: f.read(block_size), b''):
            sha256.update(block)
    return sha256.hexdigest()


def submit2cuckoo(myfile, vpn, ftype):
    stime = randint(20,25)
    logger.info(mytime + ' submitting : ' + myfile)
    url = "http://127.0.0.1:8090/tasks/create/file"
    files = dict(
        file=open(myfile, "rb"),
        filename=os.path.basename(myfile)
    )
    vpns = ["AUMelbourne", "AUSydney", "Austria", "Belgium", "Brazil", "CAMontreal", "CAToronto", "CAVancouver", "CzechRepublic", "DEBerlin", "DEFrankfurt", "Denmark", "Finland", "France", "HongKong", "Hungary", "India", "Ireland", "Israel", "Italy", "Japan", "Luxembourg", "Mexico", "Netherlands", "NewZealand", "Norway", "Poland", "Romania", "Singapore", "SouthAfrica", "Spain", "Sweden", "Switzerland", "Turkey", "UAE", "UKLondon", "UKManchester", "UKSouthampton", "USAtlanta", "USCalifornia", "USChicago", "USDenver", "USEast", "USFlorida", "USHouston", "USLasVegas", "USMidwest", "USNewYorkCity", "USSeattle", "USSiliconValley", "USTexas", "USWashingtonDC", "USWest" ]
    with open(myfile, 'rb') as sample:
        if vpn:
            data = dict(options='route=' + random.choice(vpns) + ',procmemdump=yes',
                        owner=owner, tlp='green', timeout=stime, enforce_timeout=True, priority=1)
        else:
            data = dict(options='procmemdump=yes', owner=owner, tlp='green', timeout=stime,
                        enforce_timeout=True, priority=1)
        if ftype:
            data['package'] = ftype
        #return
        r = requests.post(url, files=files, data=data)
        logger.info(mytime + " " + str(r))

def dupeCheck(myhash):
    logger.debug(mytime + " Checking existing store for Sample " + myhash)
    for root, dirs, files in os.walk(storagedir):
        for name in files:
            if myhash in name:
                logger.debug(mytime + ' already have the file ' + myhash)
                return True
            else:
                return False



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
    elif ext == "PE/Exe":
        ex = '.exe'
        ofile = storagedir + '/' + yrule + '/' + myhash + ex
    else:
        ofile = storagedir + '/' + yrule + '/' + myhash
    logger.debug(mytime + " Checking existing store for Sample " + ofile)
    logger.info(mytime + ' downloading file ' + myhash)
    response = requests.get("https://a1000.reversinglabs.com/api/samples/" + myhash + "/download/",
                            headers={"Authorization": "Token %s" % token})
    logger.debug(mytime + " " + str(response))
    downloaded_file = response.content
    f = open(ofile, 'w')
    f.write(downloaded_file)
    f.close()
    mysha256=sha256_checksum(ofile)
    mysha1=sha1_checksum(ofile)

    if myhash != mysha256 and myhash != mysha1:
        logger.debug('sha1= '+str(mysha1))
        logger.debug('sha256= '+str(mysha256))
        logger.debug('myhash='+str(myhash))
        logger.warn(mytime + " File downloaded doesn't match hash")
        return
    else:
        logger.info(mytime + " Downloaded file hash matches")
    if (ext == "MS Word Document") or (ext == "Rich Text Format") or (ext == "MicrosoftWord:Generic"):
        submit2cuckoo(ofile, True, 'doc')
    else:
        logger.info(mytime + " No matching extension")
        submit2cuckoo(ofile, True, None)
    return


def getFileList():
    params = {'apikey': akey}
    response = requests.get('https://www.virustotal.com/intelligence/hunting/notifications-feed/?key=' + akey)
    results = ""
    for r in response:
        results = results + r
    return results


def getRLFileList(yruleset):
    res = requests.get("https://a1000.reversinglabs.com/api/yara/ruleset/matches/?name="+yruleset,
                       headers={"Authorization": "Token %s" % token})
    hits = json.loads(res.content)
    return hits["results"]



yrulelist = ["ruleset1","ruleset2"]

session = db.Session()
for yruleset in yrulelist:
    myf = getRLFileList(yruleset)
    if myf:
        hcount = len(myf)
        logger.info(mytime + ' Going through ' + str(hcount) + ' files from ReversingLabs')
        for h in myf:
            created = h['created']
            cdate = None
            try:
                cdate = datetime.strptime(created.split('.')[0], '%Y-%m-%dT%H:%M:%S')
            except:
                pass
            if not cdate:
                try:
                    cdate = datetime.strptime(created, '%Y-%m-%dT%H:%M:%SZ')
                except:
                    print 'date is fucked: '+str(created)
            age = rnow - cdate
            if age:
                logger.info('age='+str(age))
                yrule = h['rule']
                myhash = h['sha1']
                ext = h['file_type']
                s = h['file_size']
                ruleset = h['rule']
                if myhash:
                    dupe = mongo.analysis.find_one({"target.file.sha1": myhash}, {"_id": 1}) or session.query(Sample).filter_by(sha1=myhash).first()
                    if dupe:
                        logger.warn("Hash {0} is a duplicate".format(str(myhash)))
                        continue
                    logger.debug(mytime + ' - ' + ruleset + ' - ' + yrule + ' - ' + myhash)
                    if (s < 7168):
                        logger.debug(mytime + ' File too small, not going further')
                    elif myhash == 'da39a3ee5e6b4b0d3255bfef95601890afd80709':
                        logger.info(mytime + ' File is empty for some reason')
                    else:
                        if ruleset:
                            dlFile(myhash, yrule, ext)
