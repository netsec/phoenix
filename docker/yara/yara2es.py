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
                parent_command_line = next(
                    par for par in hit["behavior"]["processes"] if par["pid"] == process["parent"])
                process["parent_command_line"] = parent_command_line["command_line"]
                dropped_file["command_line"].append(process)
            body["file_dropped"].append(dropped_file)
    return body


def ruleCallback(data, filename):
    if data["matches"]:
        data.pop("strings")
        data["tlp"] = tlp
        data["username"] = owner
        data["uuid"] = uuid
        data["run_date"] = now.strftime("%B %D %Y, %I:%M %p")
        data["raw_filename"] = filename
        anal_id = int(filename.split("/")[2])
        data["analysis_id"] = int(anal_id)
        data["alert"] = dict(signature=data["rule"])
        data = getMore(anal_id, filename.split("/")[-1], data)
        index_yara(data)


def scan_files(rules_path, folder_path):
    rules = yara.compile(filepath=rules_path)
    for root, directories, files in os.walk(folder_path):
        for analysis_file in files:
            filename = os.path.join(root, analysis_file)
            rules.match(filename, callback=lambda rule_data: ruleCallback(rule_data, filename))

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

    parser.add_argument('-s', '--scan_dir',
                        action='store',
                        default=os.getcwd(),
                        help='Path to the directory of files to scan (optional otherwise current dir is scanned)')

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
    scan_files(args.yara_dir, args.scan_dir)


if __name__ == "__main__":
    main()
