# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import calendar
import datetime
import json
import os
import re
import sys
import urllib
import zipfile
import logging

from cStringIO import StringIO

from bson.objectid import ObjectId
from django.conf import settings
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required, user_passes_test

from django.shortcuts import render, redirect
from django.views.decorators.http import require_safe
from django.views.decorators.csrf import csrf_exempt, ensure_csrf_cookie

import pymongo
from bson.objectid import ObjectId
from django.core.exceptions import PermissionDenied, ObjectDoesNotExist
from gridfs import GridFS
from web.tlp_methods import get_tlp_users, create_tlp_query, get_mongo_tlp_query_object

sys.path.insert(0, settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_COMPLETED

from lib.cuckoo.common.constants import CUCKOO_ROOT, LATEST_HTTPREPLAY

from lib.bluecoat_sitereview.bluecoat_sitereview import bluecoat_sitereview

from pymongo import MongoClient
from elasticsearch import Elasticsearch
from web.tlp_methods import get_es_tlp_query
log = logging.getLogger(__name__)
results_db = settings.MONGO
fs = GridFS(results_db)
domains = set()
for domain in open(os.path.join(CUCKOO_ROOT, "data", "whitelist", "domain.txt")):
    domains.add(domain.strip())

db = Database()


def get_es_data(search,user):
    client = settings.ELASTIC
    amber_users = get_tlp_users(user)
    query = get_es_tlp_query(json.loads(search), user.username, amber_users, "owner")
    query_body = {
        "from": "0",
        "size": "200",
        "query": {
            "bool": query}
    }
    cursor = client.search("cuckoo-*", body=query_body )
    return cursor


def get_mongo_data(search, user):
    # TODO: Make Mongo host config-based
    client = settings.MONGO
    tlp_part = get_mongo_tlp_query_object(user.username, get_tlp_users(user))

    query_parts = [tlp_part]
    # query_parts.append({"info.category": "file"})
    if search:
        query_parts.append(json.loads(search))
    query = {"$and": query_parts}

    cursor = client.analysis.find(query,
                                  {"info.category": "1", "info.id": "1", "info.ended": "1", "target.file.md5": "1",
                                   "target.file.name": "1","target.url": "1", "behavior.processes": "1", "network.http_ex": "1",
                                   "network.https_ex": "1", "_id":"0"}).sort("info.ended", -1).limit(200)
    return cursor


# TODO: Dont CSRF exempt
@login_required
def index(request):
    # db = Database()
    # # TODO: add stuff for when user is not logged in
    # tasks_files = db.list_tasks(limit=200, category="file", not_status=TASK_PENDING, tlpuser=request.user.username,
    #                             tlpamberusers=get_tlp_users(request.user))
    # tasks_urls = db.list_tasks(limit=200, category="url", not_status=TASK_PENDING, tlpuser=request.user.username,
    #                            tlpamberusers=get_tlp_users(request.user))
    #
    with open(os.path.join(CUCKOO_ROOT, "web", "advanced_search", "search", "fields.json"), 'r') as f:
        fields = json.load(f)

    lastRules = request.POST.get("lastRules")
    log.info(lastRules)

    posted_query = request.POST.get("query")
    if not posted_query:
        return render(request, "advanced_search/index.html", {
        "files": [],
        "fields": fields,
        "lastSearch": lastRules,
        "moloch_url": ''
    })
    cursor = get_es_data(posted_query, request.user)
    # mongo_expl = cursor.explain()
    analyses_files = [c["_source"]["table_data"] for c in cursor["hits"]["hits"]]

    # analysis_numbers = []
    # for mongo_obj in mongo_data:
    #     analysis_numbers.append(mongo_obj["info"]["id"])
    #
    #     category = mongo_obj['info']['category']
    #     new = dict(md5=mongo_obj["target"]["file"]["md5"] if category == "file" else mongo_obj["target"]["url"],
    #                ended=mongo_obj["info"]["ended"], id=mongo_obj["info"]["id"])
    #     if 'behavior' in mongo_obj:
    #         new["processes"] = mongo_obj["behavior"]["processes"]
    #     myhttp = []
    #     if ('network' in mongo_obj) and ('https_ex' in mongo_obj["network"]):
    #         for mht in list(mongo_obj["network"]["https_ex"] + mongo_obj["network"]["http_ex"])[:4]:
    #             if mht["host"] not in domains:
    #                 full_url = mht["protocol"] + '://' + mht["host"] + '/' + mht["uri"]
    #                 # TODO: Fix Bluecoat
    #                 # mycat = bluecoat_sitereview(full_url)
    #                 mht["full_url"] = full_url
    #                 # mht["category"] = mycat
    #                 myhttp.append(mht)
    #
    #     if myhttp:
    #         new["http"] = myhttp
    #
    #     filename = os.path.basename(mongo_obj["target"]["file"]["name"]) if category == "file" else "N/A"
    #     new.update({"filename": filename})
    #     analyses_files.append(new)
    moloch_url = 'https://{0}{1}/sessions?date=2180&expression=(tags==[{2}])'.format(settings.MOLOCH_HOST,
                                                                                     ":" + settings.MOLOCH_PORT if settings.MOLOCH_PORT else "",
                                                                                     ",".join(
                                                                                         ["cuckoo:" + str(analysis["id"]) for
                                                                                          analysis in
                                                                                          analyses_files]))


    return render(request, "advanced_search/index.html", {
        "files": analyses_files,
        "fields": fields,
        "lastSearch": lastRules,
        "moloch_url": moloch_url
    })
