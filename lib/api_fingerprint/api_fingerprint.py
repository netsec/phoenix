#!/usr/bin/python
import json
import pprint
import argparse

import os
from pymongo import MongoClient

# TODO: Get this from config
mhost = "172.18.1.254"
mport = 27017
families = []

profiles = []
debug = False


def gte(value, operand):
    return int(value) >= int(operand)


def lte(value, operand):
    return int(value) <= int(operand)


def between(value, operand):
    components = operand.split(':')
    if len(components) != 2:
        raise Exception("between should have 2 components")
    return int(components[0]) <= value <= int(components[1])


def equals(value, operand):
    return int(value) == int(operand)


processor = {
    "gte": gte,
    "lte": lte,
    "between": between,
    "equals": equals
}

with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'api_profiles.json')) as f:
    profiles = json.load(f)
process_names = map(lambda apimodel: apimodel["process_name"], profiles)


def process_criterion(value, operator, operand):
    return processor[operator](value, operand)


def run_api(process, model):
    fam = model["family_name"]
    for api in model["apis"]:
        apiname = api["name"]
        if apiname not in process:
            if debug:
                print "{0} not in process summary".format(apiname)
            return False
        apidata = process[apiname]
        if not process_criterion(apidata, api["operator"], api["operand"]):
            if debug:
                print "\"{0}\" - \"{1}\" operator \"{2}\" expected {3} got {4}".format(fam, apiname, api["operator"], api["operand"],apidata)
            else:
                return False
    return True


def run_all(collection=None):
    if not collection:
        mclient = MongoClient(mhost, mport)
        mydb = mclient["cuckoo"]
        collection = mydb["analysis"]
    for i in range(1, 16000):
        if debug:
            print "processing {0}".format(i)
        yield run_one(i, collection=collection)


def run_one(task_id, collection=None):
    # print "processing {0}".format(i)
    if not collection:
        print "TaskID: "+str(task_id)
        mclient = MongoClient(mhost, mport)
        mydb = mclient["cuckoo"]
        collection = mydb["analysis"]

    hits = collection.find({"info.id": task_id}, {"behavior.generic": 1,"behavior.apistats":1})
    for hit in hits:
        yield process_mongo_obj(hit)


def process_mongo_obj(hit):
    families = []
    if "behavior" not in hit or "generic" not in hit["behavior"] or "apistats" not in hit["behavior"]:
        return
    apistats = hit["behavior"]["apistats"]
    for process in hit["behavior"]["generic"]:
        process_name = process["process_name"]
        pid = str(process["pid"])
        if process_name in process_names and pid in apistats:
            models = filter(lambda apimodel: apimodel["process_name"] == process["process_name"], profiles)
            for model in models:
                if run_api(apistats[pid], model):
                    families.append(dict(process=process_name, families=model["family_name"]))
    return families


def main():
    parser = argparse.ArgumentParser("Beastmode Secret Sauce, for operators only")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-e", "--event", help="Event ID to process", type=int)
    group.add_argument("-a", "--all", help="Run on all events")
    parser.add_argument("-d", "--debug", action='store_true', help="Prints what makes it not match")
    arguments = parser.parse_args()
    mclient = MongoClient(mhost, mport)
    mydb = mclient["cuckoo"]
    mycol = mydb["analysis"]
    if arguments.debug:
        global debug
        debug = True
    if arguments.all:
        ctr = 1
        for result in run_all():
            if result:
                print str(ctr) + " " + str(result)
            ctr += 1
    if arguments.event:
        for result in run_one(arguments.event, mycol):
            print result

    # ctr = 1
    # for result in run_all():
    #     if result:
    #         print str(ctr)+" "+str(result)
    #     ctr+=1


if __name__ == "__main__":
    main()
