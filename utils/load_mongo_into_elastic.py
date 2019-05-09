import sys

import os

import pymongo

sys.path.insert(0, os.path.join(os.path.abspath(os.path.dirname(__file__)), ".."))

from lib.cuckoo.common.config import Config
from modules.reporting.elasticsearch import ElasticSearch, add_data_to_object, add_observables_to_object
import logging

logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
rootLogger = logging.getLogger()
rootLogger.setLevel(logging.INFO)
fileHandler = logging.FileHandler("{0}/{1}.log".format("/var/log/cuckoo", "mongo_load"))
fileHandler.setFormatter(logFormatter)
rootLogger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)

cfg = Config("reporting")

MONGO_HOST = cfg.mongodb.get("host", "127.0.0.1")
MONGO_PORT = cfg.mongodb.get("port", 27017)
MONGO_DB = cfg.mongodb.get("db", "cuckoo")
db = pymongo.MongoClient(MONGO_HOST, MONGO_PORT)[MONGO_DB]
# docs = db.analysis.aggregate([{'$group':{'_id':"$info.id",'entry':{'$push':{'doc':'$$ROOT'}}}}], allowDiskUse=True)

elastic = ElasticSearch()
elastic.set_options(cfg.elasticsearch)
elastic.connect()
es = elastic.es
es_documents = {}
for i in range(0, 235467):
    docs = db.analysis.find({"info.id":i}).sort([("_id",-1)]).limit(1)
    doc = None
    for item in docs:
        doc = item
        break
    if doc == None:
        rootLogger.info("No document for {0}".format(str(i)))
        continue

    task_id = ""
    try:
        task_id = doc['info']['id']
        obj = {
            "tlp": doc['info']['tlp'],
            "owner": doc['info']['owner'],
            "task_id": task_id,
            "report_id": task_id
        }
        dated_index = elastic.dated_index
        rootLogger.info("Indexing document for Task {0} to {1}".format(str(task_id), dated_index))
        add_observables_to_object(obj, doc)
        add_data_to_object(obj, doc)
        es.index(
            index=dated_index, doc_type=elastic.report_type, body=obj, id=task_id
        )
    except Exception as e:
        rootLogger.exception("Indexing document {0} failed".format(str(task_id)))
#
# for task_id, obj in es_documents.iteritems():
#     try:
#         rootLogger.info("Indexing Task {0} to {1}".format(str(task_id), dated_index))
#         es.index(
#             index=dated_index, doc_type=elastic.report_type, body=obj, id=task_id
#         )
#     except Exception as e:
#         rootLogger.exception("Indexing {0} failed".format(str(task_id)))
