# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import mimetypes
import os
import json
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
analyses_storage = os.path.abspath(os.path.join(analyses_prefix, os.pardir))
# source_for_suri_yaml =
source_for_suri_yaml = settings.SURICATA_PATH
jobSplitLength = 100
mon = datetime.now().strftime('%Y%m%d')
es = settings.ELASTIC

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
        query_template = '{"from": 0, "size": 10, "query":{"bool":{"must":[{"term":{"username.raw":"' + request.user.username + '"}},'
        yara_query = query_template + '{"term":{"_type":"yara"}}]}}}'
        suri_query = query_template + '{"term":{"_type":"suricata"}}]}}}'
        yara_hunts = es.search(index="hunt-*", body=yara_query)
        suricata_hunts = es.search(index="hunt-*", body=suri_query)
        analyses_yhunts = [convert_hit_to_template(c) for c in yara_hunts['hits']['hits']]
        analyses_surihunts = [convert_hit_to_template(c) for c in suricata_hunts['hits']['hits']]
        return render(request, "hunting/index.html",
                      {'yara_hunts': analyses_yhunts, 'suricata_hunts': analyses_surihunts})
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

        client = docker.DockerClient()

        usersInGroup = get_tlp_users(request.user)
        username = request.user.username
        analyses_numbers = get_analyses_numbers_matching_tlp(username, usersInGroup)

        # analyses = results_db.analysis.find({}, {"info.id": "1"})
        hunting_prefix = os.path.join(analyses_prefix, ".hunting/")
        hunting_uuid = os.path.join(hunting_prefix, strUuid)
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


def chunker(xs, n):
    """Yield successive n-sized chunks from l."""
    L = len(xs)
    if (n > L) or (L < 100):
        return [xs]
    assert 0 < n <= L
    s, r = divmod(L, n)
    t = s + 1
    return ([xs[p:p + t] for p in range(0, r * t, t)] +
            [xs[p:p + s] for p in range(r * t, L, s)])


def kick_off_suricata(analyses_numbers, client, hunting_uuid, strUuid, suriRuleFile, tlp, username):
    slices = chunker(analyses_numbers, settings.MAX_SURICATA_WORKERS)
    for idx, slice in enumerate(slices):
        slice_dir = hunting_uuid + '/' + str(idx)
        os.makedirs(slice_dir)
        with open(os.path.join(slice_dir, "all.rules"), 'wb+') as destination:
            for chunk in suriRuleFile.chunks():
                destination.write(chunk)
        shutil.copy(source_for_suri_yaml, slice_dir)
        with open(os.path.join(slice_dir, "infiles"), 'wb+') as infiles:
            # start_index = idx * jobSplitLength
            # end_index = start_index + jobSplitLength - 1 if len(
            #     analyses_numbers) > start_index + jobSplitLength else len(analyses_numbers) - 1
            for number in slice:
                infiles.write('/input/' + str(number) + '/dump.pcap\n')
        client.containers.run(settings.SURICATA_DOCKER_IMAGE,
                              "{0} {1} {2} {3} {4}".format(strUuid, username, tlp, idx, settings.ELASTIC_HOSTS[0]),
                              detach=True,
                              volumes={analyses_prefix: {'bind': '/input', 'mode': 'rw'}},
                              mem_limit='2g',
                              stderr=True,
                              labels={'uuid': strUuid},
                              network="docker_phoenix"
                              # ,
                              # remove=True)
                              )


def kick_off_yara(analyses_numbers, client, hunting_uuid, strUuid, yaraRuleFile, tlp, username):
    number_set = set(analyses_numbers)
    yara_malware_folder, yara_root_folder, yara_rule_file_path, yara_rules_folder, yara_target_files = get_yara_paths(
        hunting_uuid)
    os.makedirs(yara_rules_folder)
    os.makedirs(yara_malware_folder)
    # write yara rule file to new yara hunt dir
    volumes = {yara_root_folder: {'bind': '/yara', 'mode': 'rw'},
               analyses_storage: {'bind': analyses_storage, 'mode': 'ro'}}

    with open(yara_rule_file_path, 'wb+') as yara_destination:
        for chunk in yaraRuleFile.chunks():
            yara_destination.write(chunk)

    targets = []

    # create symlinks for all TLP approved files
    for number in number_set:
        analysis_folder = os.path.join(analyses_prefix, number)
        yara_malware_instance_folder = os.path.join(analyses_prefix, number)
        # yara_malware_instance_folder = os.path.join(yara_malware_folder, number)
        # os.makedirs(yara_malware_instance_folder)
        analysis_memory_path = os.path.join(analysis_folder, "memory")
        if os.path.exists(analysis_memory_path):
            print analysis_memory_path
            # volumes[analysis_memory_path] = {'bind': os.path.join(yara_malware_instance_folder, "memory"), 'mode': 'ro'}
            targets.append(os.path.join(yara_malware_instance_folder, "memory"))
            # os.symlink(analysis_memory_path, os.path.join(yara_malware_instance_folder, "memory"))

        analysis_buffer_path = os.path.join(analysis_folder, "buffer")
        if os.path.exists(analysis_buffer_path):
            print analysis_buffer_path
            targets.append(os.path.join(yara_malware_instance_folder, "buffer"))
            # volumes[analysis_buffer_path] = {'bind': os.path.join(yara_malware_instance_folder, "buffer"), 'mode': 'ro'}
            # os.symlink(analysis_buffer_path, os.path.join(yara_malware_instance_folder, "buffer"))

        analysis_files_path = os.path.join(analysis_folder, "files")
        if os.path.exists(analysis_files_path):
            print analysis_files_path
            # volumes[analysis_files_path] = {'bind': os.path.join(yara_malware_instance_folder, "files"), 'mode': 'ro'}
            targets.append(os.path.join(yara_malware_instance_folder, "files"))
            # os.symlink(analysis_files_path, os.path.join(yara_malware_instance_folder, "files"))

        binary_file_path = os.path.join(analysis_folder, "binary")
        if os.path.exists(binary_file_path):
            print binary_file_path
            # volumes[analysis_files_path] = {'bind': os.path.join(yara_malware_instance_folder, "files"), 'mode': 'ro'}
            targets.append(os.path.join(yara_malware_instance_folder, "binary"))
            # os.symlink(analysis_memory_path, os.path.join(yara_malware_instance_folder, "binary"))
    with open(os.path.join(yara_root_folder, "targets"), 'w+') as target_file:
        target_file.writelines([line + "\n" for line in targets])

    print volumes
    yara_container = client.containers.run(settings.YARA_DOCKER_IMAGE,
                                           command="{0} {1} {2} {3} {4} {5} {6}".format(
                                               "-y {0}".format(yara_rule_file_path),
                                               "-s {0}".format(yara_target_files),
                                               "-o {0}".format(username),
                                               "-t {0}".format(tlp),
                                               "-u {0}".format(strUuid),
                                               "-m {0}".format(settings.MONGO_HOST),
                                               "-e {0}".format(settings.ELASTIC_HOSTS[0])),
                                           stderr=True,
                                           labels={'uuid': strUuid},
                                           volumes=volumes,
                                           network="docker_phoenix",
                                           detach=True)


def get_yara_paths(hunting_uuid):
    yara_root_folder = os.path.join(hunting_uuid, "yara")
    yara_target_files = os.path.join(analyses_prefix, hunting_uuid, "yara/targets")
    yara_rules_folder = os.path.join(yara_root_folder, "rules")
    yara_malware_folder = os.path.join(yara_root_folder, "malware")
    yara_rule_file_path = os.path.join(yara_rules_folder, "yararules.yar")
    return yara_malware_folder, yara_root_folder, yara_rule_file_path, yara_rules_folder, yara_target_files


@login_required
def yara_file(request, hunt_uuid):
    hunting_prefix = analyses_prefix + ".hunting/"
    hunting_uuid = hunting_prefix + hunt_uuid
    yara_malware_folder, yara_root_folder, yara_rule_file_path, yara_rules_folder, yara_target_files = get_yara_paths(
        hunting_uuid)
    with open(yara_rule_file_path, 'rb') as f:
        response = HttpResponse(f, mimetypes.guess_type(yara_rule_file_path)[0])
        response['Content-Disposition'] = 'attachment; filename="yararules.yar"'
        return response


@login_required
def suri_file(request, hunt_uuid):
    hunting_prefix = os.path.join(analyses_prefix, ".hunting")
    hunting_uuid = os.path.join(hunting_prefix, hunt_uuid)
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
