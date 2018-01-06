# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import mimetypes
import os
import shutil
import sys
import traceback
import uuid
from datetime import datetime
from time import time

import docker
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import redirect
from django.shortcuts import render
from django.views.decorators.http import require_safe
from elasticsearch import Elasticsearch
from helpers import convert_hit_to_template
from web.tlp_methods import get_tlp_users, create_tlp_query, get_analyses_numbers_matching_tlp

sys.path.insert(0, settings.CUCKOO_PATH)
# analyses_prefix =
analyses_prefix = settings.ANALYSES_PREFIX
# source_for_suri_yaml =
source_for_suri_yaml = settings.SURICATA_PATH
eshost = "10.200.10.20:9200"
jobSplitLength = 100
mon = datetime.now().strftime('%Y%m%d')
es = Elasticsearch(eshost)

results_db = settings.MONGO


def timing(f):
    def wrap(*args):
        time1 = time()
        ret = f(*args)
        time2 = time()
        print '%s function took %0.3f ms' % (f.func_name, (time2 - time1) * 1000.0)
        return ret

    return wrap


@require_safe
@login_required
def index(request):
    if request.user.is_authenticated():
        query_template = '{"from": 0, "size": 10, "query":{"bool":{"must":[{"term":{"username":"'+request.user.username + '"}},'
        yara_query = query_template + '{"term":{"_type":"yara"}}]}}}'
        suri_query = query_template + '{"term":{"_type":"suricata"}}]}}}'
        yara_hunts = es.search(index="hunt-*", body=yara_query)
        suricata_hunts = es.search(index="hunt-*", body=suri_query)
        analyses_yhunts = [convert_hit_to_template(c) for c in yara_hunts['hits']['hits']]
        analyses_surihunts = [convert_hit_to_template(c) for c in suricata_hunts['hits']['hits']]
        return render(request, "hunting/index.html", {'yara_hunts': analyses_yhunts, 'suricata_hunts': analyses_surihunts})
    else:
        return redirect("/login?next=/hunting")


@login_required
def report(request, task_id=None):
    if not task_id:
        return render(request, "hunting/index.html")

    query = create_tlp_query(request.user, {"term": {"uuid.raw": task_id}})
    record = es.search(index="hunt-*", body=query)
    return render(request, "hunting/report.html",
                  {'results': [convert_hit_to_template(c) for c in record['hits']['hits']]})


@login_required
def submit(request):
    print "Submit"
    try:
        suriFiles = request.FILES.getlist("suricataRulesFile")
        yaraFiles = request.FILES.getlist("yaraRulesFile")
        tlp = request.POST.get("tlp")
        if len(suriFiles) == 0 and len(yaraFiles) == 0:
            return render(request, "hunting/index.html")

        strUuid = str(uuid.uuid4())

        client = docker.DockerClient(version='auto')

        usersInGroup = get_tlp_users(request.user)
        username = request.user.username
        analyses_numbers = get_analyses_numbers_matching_tlp(username, usersInGroup)

        # analyses = results_db.analysis.find({}, {"info.id": "1"})
        hunting_prefix = analyses_prefix + ".hunting/"
        hunting_uuid = hunting_prefix + strUuid
        os.makedirs(hunting_uuid)

        #       Workaround for TLP
        #        analyses = results_db.getCollection('analysis').find({"info.options":/yellow/},{"info":"1"})
        # analyses_numbers = [f for f in os.listdir(analyses_prefix) if str(f).isdigit()]
        if yaraFiles:
            yaraRuleFile = yaraFiles[0]
            kick_off_yara(analyses_numbers, client, hunting_uuid, strUuid, yaraRuleFile, tlp, username)
        elif suriFiles:
            suriRuleFile = suriFiles[0]
            kick_off_suricata(analyses_numbers, client, hunting_uuid, strUuid, suriRuleFile, tlp, username)

        return redirect('hunting.views.status', task_id=strUuid)
    except Exception as e:
        return HttpResponse(str(e.message) + " " + str(traceback.format_exc()))


def kick_off_suricata(analyses_numbers, client, hunting_uuid, strUuid, suriRuleFile, tlp, username):
    for i in range(0, int(len(analyses_numbers) / jobSplitLength) + 1):
        slice_dir = hunting_uuid + '/' + str(i)
        os.makedirs(slice_dir)
        with open(slice_dir + "/all.rules", 'wb+') as destination:
            for chunk in suriRuleFile.chunks():
                destination.write(chunk)
        shutil.copy(source_for_suri_yaml, slice_dir)
        with open(slice_dir + "/infiles", 'wb+') as infiles:
            start_index = i * jobSplitLength
            end_index = start_index + jobSplitLength - 1 if len(
                analyses_numbers) > start_index + jobSplitLength else len(analyses_numbers) - 1
            for number in analyses_numbers.__getslice__(start_index, end_index):
                infiles.write('/input/' + str(number) + '/dump.pcap\n')
        container = client.containers.run('7980d1615685',
                                          '/input/.hunting/.scripts/suri.py ' + strUuid + ' ' + username + ' ' + tlp + ' ' + str(
                                              i),
                                          detach=True,
                                          volumes={analyses_prefix: {'bind': '/input', 'mode': 'rw'}},
                                          mem_limit='16g',
                                          stderr=True,
                                          labels={'uuid': strUuid}
                                          )


def kick_off_yara(analyses_numbers, client, hunting_uuid, strUuid, yaraRuleFile, tlp, username):
    yara_hunt_folder = os.path.join(hunting_uuid, "yara")
    yara_malware_folder = os.path.join(yara_hunt_folder, "malware")
    os.makedirs(yara_malware_folder)
    # write yara rule file to new yara hunt dir
    volumes = {yara_hunt_folder: {'bind': '/rules', 'mode': 'rw'}}
    yara_rule_file_path = os.path.join(yara_hunt_folder, "yararules.yar")
    with open(yara_rule_file_path, 'wb+') as yara_destination:
        for chunk in yaraRuleFile.chunks():
            yara_destination.write(chunk)

    # create symlinks for all TLP approved files
    for number in analyses_numbers:
        analysis_folder = os.path.join(analyses_prefix, number)
        yara_malware_instance_folder = os.path.join("/input", number)
        # os.makedirs(yara_malware_instance_folder)

        analysis_memory_path = os.path.join(analysis_folder, "memory")
        if os.path.exists(analysis_memory_path):
            print analysis_memory_path
            volumes[analysis_memory_path] = {'bind': os.path.join(yara_malware_instance_folder, "memory"), 'mode': 'ro'}

            # os.symlink(analysis_memory_path, os.path.join(yara_malware_instance_folder, "memory"))

        analysis_buffer_path = os.path.join(analysis_folder, "buffer")
        if os.path.exists(analysis_buffer_path):
            print analysis_buffer_path
            volumes[analysis_buffer_path] = {'bind': os.path.join(yara_malware_instance_folder, "buffer"), 'mode': 'ro'}

        analysis_files_path = os.path.join(analysis_folder, "files")
        if os.path.exists(analysis_files_path):
            print analysis_files_path
            volumes[analysis_files_path] = {'bind': os.path.join(yara_malware_instance_folder, "files"), 'mode': 'ro'}

            # os.symlink(os.path.join(analysis_folder, "memory"), os.path.combine(yara_hunt_folder, number, "memory"))
    print volumes
    yara_container = client.containers.run(settings.YARA_DOCKER_IMAGE,
                                           command="{0} {1} {2} {3} {4}".format("-y /rules/yararules.yar",
                                                                                "-s /input/",
                                                                                "-o {0}".format(username),
                                                                                "-t {0}".format(tlp),
                                                                                "-u {0}".format(strUuid)),
                                           stderr=True,
                                           labels={'uuid': strUuid},
                                           volumes=volumes,
                                           detach=True)


@login_required
def yara_file(request, hunt_uuid):
    hunting_prefix = analyses_prefix + ".hunting/"
    hunting_uuid = hunting_prefix + hunt_uuid
    yara_file = os.path.join(hunting_uuid, "yara", "yararules.yar")
    with open(yara_file, 'rb') as f:
        response = HttpResponse(f, mimetypes.guess_type(yara_file)[0])
        response['Content-Disposition'] = 'attachment; filename="yararules.yar"'
        return response


@login_required
def suri_file(request, hunt_uuid):
    hunting_prefix = analyses_prefix + ".hunting/"
    hunting_uuid = hunting_prefix + hunt_uuid
    suri_file = os.path.join(hunting_uuid, "0", "all.rules")
    with open(suri_file, 'rb') as f:
        response = HttpResponse(f, mimetypes.guess_type(suri_file)[0])
        response['Content-Disposition'] = 'attachment; filename="all.rules"'
        return response


@login_required
def pcap(request, analysis_id):
    record = results_db.analysis.find_one({"info.id": int(analysis_id)})
    if record is None:
        return None
    else:
        return redirect('analysis.views.file', category='pcap', object_id=record["network"]["pcap_id"])


@login_required
def status(request, task_id):
    # TODO Create a library for ES stuff to remove duplication
    # record = es.search(index="*", body={"query": {'match_phrase': {'uuid': task_id}}})
    # record = results_db.analysis.find_one({'uuid': task_id})
    # if record['hits']['total'] == 0:
    client = docker.APIClient(version='auto')
    containers = client.containers(filters={'label': 'uuid=' + task_id})
    docker_count = len(containers)
    if docker_count > 0:
        return render(request, "hunting/status.html", {
            "task_id": task_id,
            "instance_count": docker_count
        })
    return redirect("hunting.views.report", task_id=task_id)
    # return redirect("analysis.views.report", task_id=task_id)
