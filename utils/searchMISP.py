#!/usr/bin/python
import urllib2
import json
import ssl
import sys
import os
import getopt
import re
import argparse
import traceback
from pathos.multiprocessing import Pool
import multiprocessing as mp

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))
from lib.cuckoo.common.config import Config

config = Config("reporting")
options = config.get("z_misp")
mymisp = options["url"]
auth_key = options["apikey"]

gcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)

  

def delete_event(eid):
    req = urllib2.Request(mymisp + '/events/' + str(eid))
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', auth_key)
    req.add_header('Accept', 'application/json')
    req.get_method = lambda: 'DELETE'
    resp = urllib2.urlopen(req, context=gcontext)
    content = json.load(resp)
    return content


def query_misp(endpoint):
    req = urllib2.Request(endpoint)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', auth_key)
    req.add_header('Accept', 'application/json')
    resp = urllib2.urlopen(req, context=gcontext)
    content = json.load(resp)
    return content


def tag_attribute(uuid, tag):
    data = ''
    req = urllib2.Request(mymisp + '/tags/attachTagToObject/' + str(uuid) + '/' + str(tag), data)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', auth_key)
    req.add_header('Accept', 'application/json')
    resp = urllib2.urlopen(req, context=gcontext)
    content = json.load(resp)
    return content


def delete_object(aid):
    req = urllib2.Request(mymisp + '/objects/delete/' + str(aid), '')
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', auth_key)
    req.add_header('Accept', 'application/json')
    resp = urllib2.urlopen(req, context=gcontext)
    content = json.load(resp)
    return content


def republish_event(eid):
    data = ""
    req = urllib2.Request(mymisp + '/events/publish/' + str(eid), data)
    req.add_header('Content-Type', 'application/json')
    req.add_header('Authorization', auth_key)
    req.add_header('Accept', 'application/json')
    resp = urllib2.urlopen(req, context=gcontext)
    content = json.load(resp)
    return content


def main(argv):
    parser = argparse.ArgumentParser(description='MISP API script')
    parser.add_argument('-s', '--search_term', help='Search Term')
    parser.add_argument('-r', '--regex', help='Regex Pattern')
    parser.add_argument('-p', '--purge', action='store_true', help='Purge the matching events')
    parser.add_argument('-e', '--event', help='Event ID, can only be used with -p for quick event delete')
    parser.add_argument('-t', '--tag', help='Tag for matching regex or search term')
    parser.add_argument('-c', '--comment', action='store_true', help='Search on Comment field instead of Value field')
    settings = parser.parse_args()



    search_term = settings.search_term
    regex = settings.regex
    purge = settings.purge
    evt = settings.event
    sarea = 'comment' if settings.comment else 'value'

    if (search_term or regex) and sarea:
        events = query_misp(mymisp + '/events/index')
        pool_threads = mp.cpu_count() * 8
        p = Pool(pool_threads)
        # results = []
        # for event in events:
        #     results.append(process_event(event, sarea, settings))
        results = [result for result in p.map(lambda x: process_event(x, sarea, settings), events) if result is not None]
        p.close()
        p.join()
        print json.dumps(results, indent=4)
        # for event in events:
        #    process_event(event, sarea, settings)

    elif evt:
        if purge:
            print 'Deleting Event ' + str(evt)
            delete_event(evt)
        else:
            print 'Purge Not specified for Event ' + str(evt)


def process_event(event, sarea, settings):
    eid = event["id"]
    euuid = event["uuid"]
    revent = query_misp(mymisp + '/events/' + str(eid))
    if ('Event' in revent) and ('Object' in revent["Event"]):
        for obj in revent["Event"]["Object"]:
            attributes = obj["Attribute"]
            oid = obj["id"]
            # print json.dumps(event, indent=4)
            for attribute in attributes:
                sf = attribute[sarea]
                if settings.regex:
                    rematch = re.search(settings.regex, sf)
                    if rematch and rematch.group(0):
                        uuid = attribute["uuid"]
                        process_tag(oid, eid, euuid, settings, uuid)
                        return attribute
                elif settings.search_term in sf:
                    uuid = attribute["uuid"]
                    process_tag(oid, eid, euuid, settings, uuid)
                    return attribute

def process_tag(oid, eid, euuid, settings, uuid):
    if settings.purge:
        delete_object(oid)
        republish_event(eid)
    if settings.tag:
        try:
            tag_attribute(uuid, settings.tag)
        except:
            raise Exception('Error tagging attribute=' + str(uuid) + ' with tag=' + str(settings.tag) + "Exception: " + traceback.print_exc())
        try:
            # print 'tagging event=' + str(euuid) + ' tag=' + str(settings.tag)
            tag_attribute(euuid, settings.tag)
        except:
            raise Exception('Error tagging event=' + str(euuid) + ' with tag=' + str(settings.tag) + "Exception: " + traceback.print_exc())
        try:
            # print 'Republishing event=' + str(eid)
            republish_event(eid)
        except:
            raise Exception('Error tagging attribute=' + str(uuid) + ' with tag=' + str(settings.tag) + "Exception: " + traceback.print_exc())


if __name__ == "__main__":
    main(sys.argv[1:])
