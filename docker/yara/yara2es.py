#!/usr/bin/env python
import argparse
import datetime
import multiprocessing
import os

import yara
from elasticsearch import Elasticsearch
from pymongo import MongoClient

my_es = "10.200.10.20:9200"
my_mongo = "10.200.10.21:27017"
now = datetime.datetime.today()
d = now.strftime("%Y%m%d")
owner = ""
uuid = ""
tlp = ""
g_rules_path = ""


def index_yara(ybody):
    es = Elasticsearch(my_es)
    es.index(index="hunt-" + d, doc_type="yara", body=ybody)


def mongoQuery(mdbquery):
    client = MongoClient(my_mongo)
    db = client.cuckoo
    cursor = db.analysis.find(mdbquery)
    return cursor


def getMore(id, fn, body):
    q = {"$and": [{"dropped.name": fn}, {"info.id": id}]}
    hits = mongoQuery(q)
    body["file_dropped"] = []
    for hit in hits:
        for h in filter(lambda x: fn == x["name"], hit["dropped"]):
            dropped_file = dict(file_path=h["filepath"], file_md5=h["md5"], file_sha1=h["sha1"],
                                file_sha256=h["sha256"], object_id=str(h["object_id"]))
            if not h["pids"]: continue
            pids = set(h["pids"])
            dropped_file["command_line"] = []
            for pr in filter(lambda pr: pr["pid"] in pids, hit["behavior"]["processes"]):
                process = dict(command_line=pr["command_line"], parent=pr["ppid"], parent_command_line=[])
                try:
                    parent_command_line = next(
                        par for par in hit["behavior"]["processes"] if par["pid"] == process["parent"])
                    process["parent_command_line"] = parent_command_line["command_line"]
                except StopIteration:
                    print "no parent command line for {0}".format(id)
                dropped_file["command_line"].append(process)
            body["file_dropped"].append(dropped_file)
    return body

#def getAnalId(filename):
#    last = os.readlink('/ssd/cuckoo/cuckoo/storage/analyses/latest').split('/')[-1]
#    for i in range(1, int(last)):
#        if os.path.exists('/ssd/cuckoo/cuckoo/storage/analyses/' + str(i) + '/binary'):
#            if os.readlink('/ssd/cuckoo/cuckoo/storage/analyses/' + str(i) + '/binary') == filename:
#                return int(i)

def ruleCallback(data, filename, anal_id):
    if data["matches"]:
        data.pop("strings")
        data["tlp"] = tlp
        data["username"] = owner
        data["uuid"] = uuid
        data["run_date"] = now.strftime("%Y-%m-%d %H:%M:%S")
        data["raw_filename"] = filename
        data["analysis_id"] = int(anal_id)
        data["alert"] = dict(signature=data["rule"])
        data = getMore(anal_id, filename.split("/")[-1], data)
        index_yara(data)


def scan_files(rules_path, folder_paths_file):
    rules = yara.compile(filepath=rules_path)
    paths = []
    with open(folder_paths_file, 'r') as folder_paths:
        for aline in folder_paths.read().splitlines():
            paths.append(aline)
    # print paths
    for path in paths:
        anal_id = path.split('/')[-2]
        if path.endswith('/binary'):
            fname = os.readlink(path)
            rules.match(fname, callback=lambda rule_data: ruleCallback(rule_data, fname, anal_id))
        else:
            for root, directories, files in os.walk(path, followlinks=True):
                for analysis_file in files:
                    filename = os.path.join(root, analysis_file)
                    #print filename
                    rules.match(filename, callback=lambda rule_data: ruleCallback(rule_data, filename, anal_id))
            # analysis_files.append(filename)

    # p = multiprocessing.Pool(12)
    # global g_rules_path
    # g_rules_path = rules_path
    # print analysis_files
    # p.map(match_rule, [x for x in analysis_files if isinstance(x, basestring)])
    # p.close()
    # p.join()


#
#
# def match_rule(filename):
#     try:
#
#         if os.path.isfile(filename):
#             print "FILE: "+filename
#             rules.match(filename, callback=lambda rule_data: ruleCallback(rule_data, filename))
#         else:
#             print "NOT A FILE: "+filename
#     except Exception as e:
#         print e.message
#     except:
#         pass
#

def main():
    parser = argparse.ArgumentParser(usage="Scan Files in a Directory with Yara Rules")
    parser.add_argument('-y', '--yara_dir',
                        action='store',
                        help='Path to Yara rules directory')

    parser.add_argument('-s', '--scan_folders',
                        action='store',
                        default=os.getcwd(),
                        help='Path to file with paths inside')

    parser.add_argument('-u', '--uuid',
                        action='store',
                        default="nouuid",
                        help='UUID of the hunt')

    parser.add_argument('-o', '--owner',
                        action='store',
                        default="no_owner",
                        help='User who submitted the hunt')
    parser.add_argument('-t', '--tlp',
                        action='store',
                        default="green",
                        help='TLP setting of the hunt')
    args = parser.parse_args()
    global owner
    owner = args.owner
    global tlp
    tlp = args.tlp
    global uuid
    uuid = args.uuid
    print args
    # print os.listdir(args.scan_folders)
    print os.listdir('/')
    scan_files(args.yara_dir, args.scan_folders)


if __name__ == "__main__":
    main()
