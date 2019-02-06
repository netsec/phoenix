#!/usr/bin/env python
import argparse
import datetime
import multiprocessing
import os, sys

import yara
import traceback
from elasticsearch import Elasticsearch
from pymongo import MongoClient
from decimal import *
my_es = ""
my_mongo = ""
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


def get_paths(numbers):

    for number in numbers:
        print "enumerating analysis {0}".format(number)
        analysis_folder = os.path.join('/analyses/analyses', number)
        yara_malware_instance_folder = os.path.join('/analyses/analyses', number)
        # yara_malware_instance_folder = os.path.join(yara_malware_folder, number)
        # os.makedirs(yara_malware_instance_folder)
        analysis_memory_path = os.path.join(analysis_folder, "memory")
        # print analysis_memory_path
        if os.path.exists(analysis_memory_path):
            # print analysis_memory_path
            # volumes[analysis_memory_path] = {'bind': os.path.join(yara_malware_instance_folder, "memory"), 'mode': 'ro'}
            yield os.path.join(yara_malware_instance_folder, "memory")
            # os.symlink(analysis_memory_path, os.path.join(yara_malware_instance_folder, "memory"))

        analysis_buffer_path = os.path.join(analysis_folder, "buffer")
        if os.path.exists(analysis_buffer_path):
            # print analysis_buffer_path
            yield os.path.join(yara_malware_instance_folder, "buffer")
            # volumes[analysis_buffer_path] = {'bind': os.path.join(yara_malware_instance_folder, "buffer"), 'mode': 'ro'}
            # os.symlink(analysis_buffer_path, os.path.join(yara_malware_instance_folder, "buffer"))

        analysis_files_path = os.path.join(analysis_folder, "files")
        if os.path.exists(analysis_files_path):
            # print analysis_files_path
            # volumes[analysis_files_path] = {'bind': os.path.join(yara_malware_instance_folder, "files"), 'mode': 'ro'}
            yield os.path.join(yara_malware_instance_folder, "files")
            # os.symlink(analysis_files_path, os.path.join(yara_malware_instance_folder, "files"))

        binary_file_path = os.path.join(analysis_folder, "binary")
        if os.path.exists(binary_file_path):
            # print binary_file_path
            # volumes[analysis_files_path] = {'bind': os.path.join(yara_malware_instance_folder, "files"), 'mode': 'ro'}
            yield os.path.join(yara_malware_instance_folder, "binary")


def scan_files(rules_path, folder_paths_file, sliceid):
    rules = yara.compile(filepath=rules_path)
    numbers = []
    paths = []
    with open(folder_paths_file, 'r') as folder_paths:
        for aline in folder_paths.read().splitlines():
            numbers.append(aline)

    paths = list(get_paths(numbers))
    num_paths_to_process = len(paths)
    paths_finished = []
    progress_pct = 0
    # print paths
    for path in paths:
        anal_id = path.split('/')[-2]
        if path.endswith('/binary'):
            try:
                fname = os.readlink(path)
                print "scanning {0}".format(fname)
                rules.match(fname, callback=lambda rule_data: ruleCallback(rule_data, fname, anal_id))
            except Exception as e:
                print traceback.print_exc()
        else:
            for root, directories, files in os.walk(path, followlinks=True):
                for analysis_file in files:
                    filename = os.path.join(root, analysis_file)
                    #print filename
                    try:
                        print "scanning {0}".format(filename)
                        rules.match(filename, callback=lambda rule_data: ruleCallback(rule_data, filename, anal_id))
                    except Exception as e:
                        print traceback.print_exc()
        paths_finished.append(path)
        num_paths_finished = len(paths_finished)
        progress_pct = Decimal(num_paths_finished) / Decimal(num_paths_to_process) * 100
        progress_info = "Paths to process: {0} Paths finished: {1} Completion Percentage: {2:.2f}%".format(
                    num_paths_to_process, num_paths_finished, progress_pct)
        print progress_info
        try:
            with open("/yara/progress_"+sliceid, 'w+') as progress_file:
                progress_file.write(progress_info)
        except Exception as prog_e:
            print "Couldn't write to progress file"
            traceback.print_exc()



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
    # decimals only to two places
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
    parser.add_argument('-m', '--mongo',
                        action='store',
                        default="",
                        help='Mongo host')
    parser.add_argument('-e', '--es',
                        action='store',
                        default="",
                        help='ES host')
    parser.add_argument('-i', '--sliceid',
                        action='store',
                        default="0",
                        help='Slice Id for reporting progress')
    args = parser.parse_args()
    global owner
    owner = args.owner
    global tlp
    tlp = args.tlp
    global uuid
    uuid = args.uuid
    global my_mongo
    my_mongo = args.mongo
    global my_es
    my_es = args.es
    print args
    # print os.listdir(args.scan_folders)
    print os.listdir('/')
    scan_files(os.path.abspath(args.yara_dir), os.path.abspath(args.scan_folders), args.sliceid)


if __name__ == "__main__":
    main()
