# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

from __future__ import absolute_import

import datetime
import json
import logging
import time
import os
import httplib

from lib.cuckoo.common.abstracts import Report
from lib.cuckoo.common.constants import CUCKOO_ROOT
from lib.cuckoo.common.exceptions import CuckooDependencyError
from lib.cuckoo.common.exceptions import CuckooReportError
from lib.cuckoo.common.utils import convert_to_printable
from lib.cuckoo.common.whitelist import is_whitelisted_url,is_whitelisted_ip,is_whitelisted_domain

logging.getLogger("elasticsearch").setLevel(logging.WARNING)
logging.getLogger("elasticsearch.trace").setLevel(logging.WARNING)

httplib._MAXHEADERS=10000

try:
    from elasticsearch import (
        Elasticsearch, ConnectionError, ConnectionTimeout, helpers
    )

    HAVE_ELASTIC = True
except ImportError:
    HAVE_ELASTIC = False

log = logging.getLogger(__name__)


def get_dict_value(obj, field, observable):
    keys = field.split('.')
    current = obj
    idx = 0
    if isinstance(current, list):
        retlist = []
        for item in current:
            items = get_dict_value(item, '.'.join(keys), observable)
            if items:
                retlist.extend(items)
        return retlist
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key, None)
            if current is None:
                return None
            return get_dict_value(current,'.'.join(keys[1:]), observable)

        if current is None or check_whitelists(current,observable) is None:
            return None
        if isinstance(current, basestring) and len(current) > 16000:
            i=0
            chunk_length=16000
            max = len(current)
            pieces = []
            while i < max:
                chunk_end = i + chunk_length
                while i < chunk_end < len(current) and current[chunk_end] != " ":
                    chunk_end -= 1
                if chunk_end == i:
                    # couldn't find a space
                    chunk_end = i+chunk_length
                piece = current[i:chunk_end]
                i += len(piece)
                pieces.append(piece)
            return pieces
            # return [current[i:i + 32765] for i in range(0, len(current), 32765)]

        return [current]

def check_whitelists(value, observable):
    if (observable == "DOMAIN" and is_whitelisted_domain(value)) or \
        (observable in ["DST","IP","SRC"] and is_whitelisted_ip(value) or \
         (observable in ["URI_PATH", "URL","URL_PATH"]) and is_whitelisted_url(value)):
        return None
    return value

def add_observables_to_object(obj,report):
    as_template = {}
    with open(os.path.join(CUCKOO_ROOT, "web", "advanced_search", "search", "fields.json"), 'r') as as_file:
        as_template = json.load(as_file)
    for observable in as_template:
        obserValues = set()
        for field in observable["fields"]:
            value = get_dict_value(report, field, observable["name"])
            if value:
                obserValues.update(value)
        obj.update({observable["name"]: list(obserValues)})
    return obj


def add_data_to_object(obj, report):
    category = report['info']['category']
    data= dict(md5=report["target"]["file"]["md5"] if category == "file" else report["target"]["url"],
               ended=report["info"]["ended"], id=report["info"]["id"])
    if 'behavior' in report:
        data["processes"] = [process["command_line"] for process in report["behavior"]["processes"]]
    myhttp = []
    if ('network' in report) and ('https_ex' in report["network"]):
        for mht in list(report["network"]["https_ex"] + report["network"]["http_ex"])[:4]:
            if not is_whitelisted_domain(mht["host"]):
                full_url = mht["protocol"] + '://' + mht["host"] + '/' + mht["uri"]
                mht["full_url"] = full_url
                myhttp.append(mht)

    if myhttp:
        data["http"] = myhttp

    filename = os.path.basename(report["target"]["file"]["name"]) if category == "file" else "N/A"
    data.update({"filename": filename})
    obj["table_data"]=data
    return obj

class ElasticSearch(Report):
    """Stores report in Elasticsearch."""

    def connect(self):
        """Connect to Elasticsearch.
        @raise CuckooReportError: if unable to connect.
        """
        hosts = []
        for host in self.options.get("hosts", "127.0.0.1:9200").split(","):
            if host.strip():
                hosts.append(host.strip())

        self.index = self.options.get("index", "cuckoo")

        # Do not change these types without changing the elasticsearch
        # template as well.
        self.report_type = "cuckoo"
        self.call_type = "call"

        # Get the index time option and set the dated index accordingly
        index_type = self.options.get("index_time_pattern", "yearly")
        if index_type.lower() == "yearly":
            strf_time = "%Y"
        elif index_type.lower() == "monthly":
            strf_time = "%Y%m"
        elif index_type.lower() == "daily":
            strf_time = "%Y%m%d"

        date_index = datetime.datetime.utcnow().strftime(strf_time)
        self.dated_index = "%s-%s" % (self.index, date_index)

        # Gets the time which will be used for indexing the document into ES
        # ES needs epoch time in seconds per the mapping
        self.report_time = int(time.time())

        try:
            self.es = Elasticsearch(hosts)
        except TypeError:
            raise CuckooReportError(
                "Elasticsearch connection hosts must be host:port or host"
            )
        except (ConnectionError, ConnectionTimeout) as e:
            raise CuckooReportError("Cannot connect to Elasticsearch: %s" % e)

        # check to see if the template exists apply it if it does not
        if not self.es.indices.exists_template("cuckoo_template"):
            if not self.apply_template():
                raise CuckooReportError("Cannot apply Elasticsearch template")

    def apply_template(self):
        template_path = os.path.join(
            CUCKOO_ROOT, "data", "elasticsearch", "template.json"
        )
        if not os.path.exists(template_path):
            return False

        with open(template_path, "rw") as f:
            try:
                cuckoo_template = json.loads(f.read())
            except ValueError:
                raise CuckooReportError(
                    "Unable to read valid JSON from the ElasticSearch "
                    "template JSON file located at: %s" % template_path
                )

            # Create an index wildcard based off of the index name specified
            # in the config file, this overwrites the settings in
            # template.json.
            cuckoo_template["template"] = self.index + "-*"

        self.es.indices.put_template(
            name="cuckoo_template", body=json.dumps(cuckoo_template)
        )
        return True

    def get_base_document(self):
        # Gets precached report time and the task_id.
        header = {
            "task_id": self.task["id"],
            "report_time": self.report_time,
            "report_id": self.task["id"]
        }
        return header

    def do_index(self, obj):
        index = self.dated_index

        base_document = self.get_base_document()
        # Append the base document to the object to index.
        # PHOENIX: Don't append the object, because the object is too deep now.  Just use search stuff.
        base_document.update(obj)

        try:
            self.es.index(
                index=index, doc_type=self.report_type, body=base_document, id=self.task["id"]
            )
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

    def do_bulk_index(self, bulk_reqs):
        try:
            helpers.bulk(self.es, bulk_reqs)
        except Exception as e:
            raise CuckooReportError(
                "Failed to save results in ElasticSearch for "
                "task #%d: %s" % (self.task["id"], e)
            )

    def process_call(self, call):
        """This function converts all arguments to strings to allow ES to map
        them properly."""
        if "arguments" not in call or type(call["arguments"]) != dict:
            return call

        new_arguments = {}
        for key, value in call["arguments"].iteritems():
            if type(value) is unicode or type(value) is str:
                new_arguments[key] = convert_to_printable(value)
            else:
                new_arguments[key] = str(value)

        call["arguments"] = new_arguments
        return call

    def process_behavior(self, results, bulk_submit_size=1000):
        """Index the behavioral data."""
        for process in results.get("behavior", {}).get("processes", []):
            bulk_index = []

            for call in process["calls"]:
                base_document = self.get_base_document()
                call_document = {
                    "pid": process["pid"],
                    "tlp": self.task["tlp"],
                    "owner": self.task["owner"]
                }
                call_document.update(self.process_call(call))
                call_document.update(base_document)
                bulk_index.append({
                    "_index": self.dated_index,
                    "_type": self.call_type,
                    "_source": call_document
                })
                if len(bulk_index) == bulk_submit_size:
                    self.do_bulk_index(bulk_index)
                    bulk_index = []

            if len(bulk_index) > 0:
                self.do_bulk_index(bulk_index)

    def run(self, results):
        """Index the Cuckoo report into ElasticSearch.
        @param results: analysis results dictionary.
        @raise CuckooReportError: if the connection or reporting failed.
        """
        if not HAVE_ELASTIC:
            raise CuckooDependencyError(
                "Unable to import elasticsearch (install with "
                "`pip install elasticsearch`)"
            )

        self.connect()
        obj={
            # "cuckoo_node": self.options.get("cuckoo_node"),
            # "target": results.get("target"),
            "tlp": self.task["tlp"],
            "owner": self.task["owner"],
            # "summary": results.get("behavior", {}).get("summary"),
            # "virustotal": results.get("virustotal"),
            # "irma": results.get("irma"),
            # "signatures": results.get("signatures"),
            # "dropped": results.get("dropped"),
        }
        add_observables_to_object(obj,results)
        add_data_to_object(obj,results)
        # Index target information, the behavioral summary, and
        # VirusTotal results.
        self.do_index(obj)

        # Index the API calls.
        if self.options.get("calls"):
            self.process_behavior(results)
