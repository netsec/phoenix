#!/usr/bin/python
import json
import pprint
import argparse

import os
from pymongo import MongoClient

mhost = "172.18.1.254"
mport = 27017
families = []

profiles = []
debug = False
process_names= ""

class APIMethod:
    def __init__(self, key, value):
        self.key = key
        self.value = value

    def __eq__(self, other):
        return self.key == other.key


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


def run_all(event_ids, collection=None):
    if not collection:
        mclient = MongoClient(mhost, mport)
        mydb = mclient["cuckoo"]
        collection = mydb["analysis"]

    hits = collection.find({"info.id": {"$in": event_ids}}, {"behavior.generic": 1, "behavior.apistats": 1})

    return process_mongo_obj(hits)

def get_other_process_objects(other_hits, process_name):
    for hit in other_hits:
        for item in hit["behavior"]["generic"]:
            if item["process_name"] == process_name:
                pid = item["pid"]
                yield hit["behavior"]["apistats"][str(pid)]


def process_mongo_obj(mongo_hits):
    hits = list(mongo_hits)
    if len(hits) <= 1:
        raise Exception("Less than 2 hits returned")
    hit = hits[0]
    other_hits = hits[1:]
    out_list = []
    if "behavior" not in hit or "generic" not in hit["behavior"]:
        return
    for process in hit["behavior"]["generic"]:
        if process["process_name"] in process_names:
            pid = process["pid"]
            process_object_list = list(get_other_process_objects(other_hits, process["process_name"]))
            str_pid = str(pid)
            for key, value in hit["behavior"]["apistats"][str_pid].iteritems():

                items = map(lambda other_hit: other_hit.get(key), process_object_list)
                if not all(items):
                    continue
                hit_one_object = hit["behavior"]["apistats"][str_pid]
                if all(map(lambda other_hit: other_hit[key] == hit_one_object[key], process_object_list)):
                    out_list.append({"name": key, "operator": "equals", "operand": hit_one_object[key]})
                else:
                    values = list(map(lambda other_hit: other_hit[key], process_object_list))
                    out_list.append({"name": key, "operator": "between", "operand": "{0}:{1}".format(min(values), max(
                        values))})
    return out_list




def main():
    parser = argparse.ArgumentParser("Beastmode Secret Sauce, for operators only")
    # group = parser.add_mutually_exclusive_group(required=True)
    parser.add_argument("-e", "--events", help="Event IDs to process",nargs="+", type=int)
    parser.add_argument("-f", "--families", nargs="+", help="Families to tag")
    # group.add_argument("-a", "--all", help="Run on all events")
    parser.add_argument("-p", "--processnames",nargs="+", help="Process name to look for")
    parser.add_argument("-d", "--debug", action='store_true', help="Prints what makes it not match")
    arguments = parser.parse_args()
    mclient = MongoClient(mhost, mport)
    mydb = mclient["cuckoo"]
    mycol = mydb["analysis"]
    global process_names
    process_names = arguments.processnames

    if arguments.debug:
        global debug
        debug = True
    # if arguments.all:
    #     ctr = 1
    #     for result in run_all():
    #         if result:
    #             print str(ctr) + " " + str(result)
    #         ctr += 1
    if arguments.events and arguments.families:
        result = run_all(arguments.events, mycol)
        output = {"process_name": process_names[0], "family_name":arguments.families, "apis":result}
        pprint.pprint(output, indent=4)

    # ctr = 1
    # for result in run_all():
    #     if result:
    #         print str(ctr)+" "+str(result)
    #     ctr+=1


if __name__ == "__main__":
    main()
