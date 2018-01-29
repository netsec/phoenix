#!/usr/bin/env python
import sys, os
#sys.path.append(os.path.join(os.path.dirname(__file__), "..","web"))

from django.conf import settings
# import pymongo, os
import traceback
from multiprocessing import Pool
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "..","web","web"))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "settings")
#from lib.cuckoo.common.constants import CUCKOO_ROOT
# host = "m0"
# port = 27017
# db = "cuckoo"


def get_mongo_client():
    try:
        return settings.MONGO
    except Exception as e:
        raise Exception("Unable to connect to Mongo: %s" % e)


# from elasticsearch import Elasticsearch
import sqlite3
#from web.tlp_methods import get_analyses_numbers_matching_tlp
sqldb = 'SQLITEPATH'
# myes = "bm-es0:9200"
domains = set()
for domain in open(os.path.join('..', "data", "whitelist", "domain.txt")):
    domains.add(domain.strip())

# mquery='''{ "query": {"match":{"userId":"'''+myuser+'''"}}}'''

def esQuery(query):
    es = settings.ELASTIC
    res = es.search(index="users_v4", body=query)
    return res


def esInsert(index, dtype, myid, body):
    es = settings.ELASTIC
    es.index(index=index, doc_type=dtype, id=myid, body=body)


#TODO: move these back to tlp_methods
def get_analyses_numbers_matching_tlp(username, usersInGroup, results_db):
    query_object = get_mongo_tlp_query_object(username, usersInGroup)
    analyses = results_db.analysis.find(query_object, {"info.id": "1"})
    analyses_numbers = [str(result["info"]["id"]) for result in analyses]
    return analyses_numbers

def get_mongo_tlp_query_object(username, usersInGroup):
    query_object = {'$or': [{'$and': [{'info.tlp': 'red'}, {'info.owner': username}]},
                            {'$and': [{'info.tlp': 'amber'}, {'info.owner': {'$in': usersInGroup}}]},
                            {'info.tlp': 'green'}]}
    return query_object

def update_moloch_tlp(user):
    try:
        myconn = sqlite3.connect(sqldb)
        other_users = myconn.cursor()
        other_users.execute('select outer_a.username from auth_user outer_a, auth_user_groups outer_g where outer_g.user_id = outer_a.id and outer_g.group_id in (select g.group_id from auth_user a, auth_user_groups g where g.user_id = a.id AND a.id="{0}");'.format(user[0]))
        other_user_list = [other_user[0] for other_user in other_users.fetchall()]
        analyses_nums = get_analyses_numbers_matching_tlp(user[1], other_user_list, get_mongo_client())
        forced_expr = "(tags == ["+",".join(["cuckoo:"+analyses_num for analyses_num in analyses_nums])+"])"
        ## To ignore whitelisted domains leave line below uncommented
        forced_expr += " && (ip.dst != [10.200.0.255,224.0.0.252,239.255.255.250]) && (host != ["+",".join(domains)+"])"
        mquery='''{ "query": {"match":{"userId":"'''+user[1]+'''"}}}'''
        esq = esQuery(mquery)
        if esq["hits"]["hits"]:
            inreq = esq["hits"]["hits"][0]
            insrc = inreq["_source"]
            insrc["expression"] = forced_expr
            esInsert(inreq["_index"],inreq["_type"],inreq["_id"], insrc)
    except: 
        print traceback.print_exc()
    finally:
        if myconn:
            myconn.close()

conn = sqlite3.connect(sqldb)
users = conn.cursor()
users.execute("select id, username from auth_user")
users_list = users.fetchall()
p = Pool(64)
p.map(update_moloch_tlp, users_list)
