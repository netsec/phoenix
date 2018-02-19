#!/usr/local/bin/python2.7
import argparse
import datetime
import json
import os

from elasticsearch import Elasticsearch
from pymongo import MongoClient
from django.conf import settings
from web.tlp_methods import get_tlp_users,get_analyses_numbers_matching_tlp

today = datetime.date.today()
now = today.strftime('%Y%m%d')
month = today.strftime('%Y%m')
httpList = []
httpMemList = []
domainList = []
ipList = []
output = {"File": {}}
myid = 0


def getList(ifile):
    with open(os.path.join(os.path.dirname(__file__), ifile)) as c:
        content = c.readlines()
        content = [x.strip() for x in content]
        return content


crls = getList("crls")
sengines = getList("search")
prefix = getList("prefix")
cliIgnore = getList("cli")


def memPrune(obj):
    return obj not in crls + sengines

def httpPrune(obj):
    dmn = obj.split("://")[1].split("/")[0]
    if dmn not in prefix:
        return True


def molochEsQuery(query):
    es = settings.ELASTIC
    res = es.search(index="sessions-*", body=query)
    return res


def mongoQuery(mdbquery):
    client = settings.MONGO
    #db = client.cuckoo
    cursor = client.analysis.find(mdbquery)
    return cursor


def EsInsert(index, dtype, myid, body):
    es = settings.ELASTIC
    res = es.index(index=index, doc_type=dtype, body=body)


def MD5Dropped(dmd5, md5src, drophit, local):
    if local:
        mquery = '''{ "query": {"match":{"hmd5":"''' + dmd5 + '''"}}}'''
    mhit = molochEsQuery(mquery)
    if not mhit["hits"]["hits"]:
        return False

    for dhit in mhit["hits"]["hits"]:
        dobj = dict(MD5=dmd5, SHA1=drophit["sha1"], Drop_File_Type=drophit["type"], File_Path=drophit["filepath"],
                    URI=dhit["_source"]["us"], Dest_Port=dhit["_source"]["p2"])

        if 'ua' in dhit["_source"].keys():
            dobj["UserAgent"] = dhit["_source"]["ua"]
        if 'ipDst' in dhit["_source"].keys():
            dobj["Dest_IP"] = dhit["_source"]["ipDst"]
        if 'virustotal' in drophit:
            if 'scans' in drophit["virustotal"].keys():
                dobj["AV_Hits"] = {}
                for vscan in drophit["virustotal"]["scans"]:
                    if drophit["virustotal"]["scans"][vscan]["detected"]:
                        dobj["AV_Hits"][vscan] = drophit["virustotal"]["scans"][vscan]["result"]
        output[md5src].append(dobj)
        return True


def MD5H(dmd5, md5src, drophit, local, md5, d):
    if md5["md5"] == dmd5:
        dobj = dict(MD5=dmd5, SHA1=drophit["sha1"], Drop_File_Type=drophit["type"], Response=md5["response"],
                    URL=md5["protocol"] + "//" + md5["host"] + md5["uri"], Dest_IP=md5["dst"],
                    Raw_Request=md5["request"], Date_Detonated=str(d["info"]["ended"]),
                    Detonated_From=d["info"]["route"], Stage_1_MD5=d["target"]["file"]["md5"],
                    Stage_1_SHA1=d["target"]["file"]["sha1"])

        if 'filepath' not in drophit:
            dobj["Name"] = drophit["name"]
        else:
            dobj["File_Path"] = drophit["filepath"]
        if 'virustotal' in drophit and 'scans' in drophit["virustotal"].keys():
            dobj["AV_Hits"] = {}
            for vscan in drophit["virustotal"]["scans"]:
                if drophit["virustotal"]["scans"][vscan]["detected"]:
                    dobj["AV_Hits"][vscan] = drophit["virustotal"]["scans"][vscan]["result"]
        if md5src not in output:
            output[md5src] = []
        if dobj not in output["Dropped_In_Other_Samples"]:
            output[md5src].append(dobj)


def MD5Https(dmd5, md5src, drophit, local):
    if dmd5 in ["d41d8cd98f00b204e9800998ecf8427e"]:
        return
    if local:
        mdbq = '''{"$and":[{"info.id":''' + str(
            myid) + '''},{"$or":[{"network.https_ex.md5":"''' + dmd5 + '''"},{"network.http_ex.md5":"''' + dmd5 + '''"}]}]}'''
    else:
        mdbq = '''{"$and":[{"info.id":{"$ne":''' + str(
            myid) + '''}},{"$or":[{"network.https_ex.md5":"''' + dmd5 + '''"},{"network.http_ex.md5":"''' + dmd5 + '''"}]}]}'''
    mdh = mongoQuery(json.loads(mdbq))
    if mdh:
        for d in mdh:
            for md5 in d["network"]["https_ex"]:
                MD5H(dmd5, md5src, drophit, local, md5, d)
            for md5 in d["network"]["http_ex"]:
                MD5H(dmd5, md5src, drophit, local, md5, d)


# Start
def run_tldr(myid, user, clionly):
    myid = int(myid)
    print(myid)
    myids = get_analyses_numbers_matching_tlp(user.username, get_tlp_users(user))
    if str(myid) in myids:
        mdbquery = {"info.id": myid}

    idcursor = mongoQuery(mdbquery)
    for doc in idcursor:
        output["File"] = dict(sha1=doc["target"]["file"]["sha1"], md5=doc["target"]["file"]["md5"],
                              sha256=doc["target"]["file"]["sha256"], type=doc["target"]["file"]["type"], AV_Hits={},
                              Command_Lines=[])
        if 'vscan' in doc["virustotal"]:
            for vscan in doc["virustotal"]["scans"]:
                if doc["virustotal"]["scans"][vscan]["detected"]:
                    output["File"]["AV_Hits"][vscan] = doc["virustotal"]["scans"][vscan]["result"]
        if 'behavior' in doc:
            for cli in doc["behavior"]["processes"]:
                if cli not in cliIgnore:
                    output["File"]["Command_Lines"].append(cli["command_line"])
        if 'procmemory' in doc:
            for pm in doc["procmemory"]:
                ntw_mem = pm["urls"]
                for ntw_mem_hit in ntw_mem:
                    if memPrune(ntw_mem_hit) and (ntw_mem_hit not in httpMemList):
                        httpMemList.append(ntw_mem_hit)
                output["URL_in_memory"] = httpMemList
        if 'network' in doc:
            for httphit in doc["network"]["http"]:
                # print httphit
                uri = httphit["uri"]
                if httpPrune(str(uri)) and uri not in httpList:
                    httpList.append(uri)
            output["HTTP"] = httpList
            for httpshit in doc["network"]["https_ex"]:
                output["HTTPS"] = []
                httpsobj = {"host": httpshit["host"], "http_method": httpshit["method"],
                            "response": httpshit["response"],
                            "response_md5": httpshit["md5"], "dst": httpshit["dst"], "uri": httpshit["uri"],
                            "raw_request": httpshit["request"]}
                output["HTTPS"].append(httpsobj)

        if 'dns' in doc["network"]:
            output["DNS"] = []
            for dns in doc["network"]["dns"]:
                if dns["request"] not in prefix:
                    dnobj = dict(domain=dns["request"], answers=dns["answers"])
                    output["DNS"].append(dnobj)

        if 'dropped' in doc:
            output["Dropped_files"] = []
            for drophit in doc["dropped"]:
                dmd5 = drophit["md5"]
                MD5Dropped(dmd5, "Dropped_files", drophit, True)
                MD5Https(dmd5, "Dropped_files", drophit, True)
                MD5Https(dmd5, "Dropped_In_Other_Samples", drophit, False)
    # outJson = json.dumps(output)
    # pretty
    outJson = json.dumps(output, indent=4, sort_keys=True)
    if clionly:
        EsInsert("tldr-"+month, "tldr", myid, outJson)
    print(outJson)
    return outJson


if __name__ == '__main__':
    clid = True
    parser = argparse.ArgumentParser()
    parser.add_argument('--id', help='cuckoo ID')
    parser.add_argument('--user', help='user ID')
    args = vars(parser.parse_args())
    run_tldr(args['id'],args['user'],True)
