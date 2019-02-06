# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.
import logging
import os
import traceback

import requests
import sys

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render
from django.core.exceptions import ObjectDoesNotExist


from analysis.models import UsageLimits

sys.path.insert(0, settings.CUCKOO_PATH)

from lib.cuckoo.common.config import Config, parse_options, emit_options
from lib.cuckoo.common.utils import store_temp_file
from lib.cuckoo.core.database import Database
# from lib.cuckoo.core.rooter import vpns
log = logging.getLogger(__name__)

results_db = settings.MONGO
db = Database()

cfg = Config()
processing_cfg = Config("processing")

def force_int(value):
    try:
        value = int(value)
    except:
        value = 0
    finally:
        return value

def dropped_filepath(task_id, sha1):
    record = results_db.analysis.find_one(
        {
            "info.id": int(task_id),
            "dropped.sha1": sha1,
        }
    )

    if not record:
        raise ObjectDoesNotExist

    for dropped in record["dropped"]:
        if dropped["sha1"] == sha1:
            return dropped["path"]

    raise ObjectDoesNotExist

@login_required
def render_index(request, kwargs={}):
    files = os.listdir(os.path.join(settings.CUCKOO_PATH, "analyzer", "windows", "modules", "packages"))

    packages = []
    for name in files:
        name = os.path.splitext(name)[0]
        if name == "__init__":
            continue

        packages.append(name)

    # Prepare a list of VM names, description label based on tags.
    machines = []
    for machine in db.list_machines():
        tags = []
        for tag in machine.tags:
            tags.append(tag.name)

        if tags:
            label = machine.label + ": " + ", ".join(tags)
        else:
            label = machine.label

        machines.append((machine.label, label))

    # Prepend ALL/ANY options.
    machines.insert(0, ("", "First available"))
    machines.insert(1, ("all", "All"))
    vpns = get_vpns()
    values = {
        "packages": sorted(packages),
        "machines": machines,
        "vpns": vpns.values(),
        "route": cfg.routing.route,
        "internet": cfg.routing.internet,
        "nogroups": request.user.groups.exists()
    }

    values.update(kwargs)
    return render(request, "submission/index.html", values)


@login_required
def index(request, task_id=None, sha1=None):
    if request.method == "GET":
        return render_index(request)

    package = request.POST.get("package", "")
    timeout = force_int(request.POST.get("timeout"))
    options = request.POST.get("options", "")
    priority = force_int(request.POST.get("priority"))
    machine = request.POST.get("machine", "")
    custom = request.POST.get("custom", "")
    memory = bool(request.POST.get("memory", False))
    enforce_timeout = bool(request.POST.get("enforce_timeout", False))
    tags = request.POST.get("tags", None)

    options = parse_options(options)

    # The following POST fields take precedence over the options field.
    if request.POST.get("route"):
        options["route"] = request.POST.get("route")

    if request.POST.get("free"):
        options["free"] = "yes"

    if request.POST.get("process_memory"):
        options["procmemdump"] = "yes"

    if request.POST.get("services"):
        options["services"] = "yes"

    if not request.POST.get("human"):
        options["human"] = "0"

    tlp = request.POST.get('tlp')
    task_ids = []
    task_machines = get_task_machines(db, machine)
    credit = UsageLimits.get_credit(request.user)
    if credit <= 0:
        return render(request, "error.html", {
            "error": "You have exceeded your daily usage.  Please try again tomorrow or request a limit increase",
        })
    # In case of resubmitting a file.
    if request.POST.get("category") == "file":
        task = db.view_task(task_id)

        for entry in task_machines:
            if not UsageLimits.take_credit(request.user):
                break
            task_id = db.add_path(file_path=task.target,
                                  package=package,
                                  timeout=timeout,
                                  options=emit_options(options),
                                  priority=priority,
                                  machine=entry,
                                  custom=custom,
                                  memory=memory,
                                  enforce_timeout=enforce_timeout,
                                  tags=tags,
                                  owner=request.user.username if request.user.is_authenticated else "",
                                  tlp=tlp)
            if task_id:
                task_ids.append(task_id)

    elif request.FILES.getlist("sample") or request.POST["vt_hashes"] or request.POST["rl_hashes"]:
        paths = []
        if request.FILES.getlist("sample"):
            samples = request.FILES.getlist("sample")
            for sample in samples:
                if not UsageLimits.take_credit(request.user):
                    break
                # Error if there was only one submitted sample and it's empty.
                # But if there are multiple and one was empty, just ignore it.
                if not sample.size:
                    if len(samples) != 1:
                        continue

                    return render(request, "error.html", {
                        "error": "You uploaded an empty file.",
                    })
                elif sample.size > settings.MAX_UPLOAD_SIZE:
                    return render(request, "error.html", {
                        "error": "You uploaded a file that exceeds that maximum allowed upload size.",
                    })

                # Moving sample from django temporary file to Cuckoo temporary
                # storage to let it persist between reboot (if user like to
                # configure it in that way).

                path = store_temp_file(sample.read(), sample.name)
                paths.append(path)
        elif request.POST["vt_apikey"]:
            #logger.info(mytime + ' downloading file')
            vt_key = request.POST["vt_apikey"]
            if not vt_key:
                return render(request, "error.html", {
                    "error": "You must supply a VT API Key.",
                })
            for vt_hash in request.POST["vt_hashes"].split():
                if not UsageLimits.take_credit(request.user):
                    break
                params = {'apikey': vt_key, 'hash': vt_hash}
                response = requests.get(processing_cfg.virustotal.get("downloadurl"), params=params)
                try:
                    response.raise_for_status()
                    path = store_temp_file(response.content, vt_hash)
                    paths.append(path)
                except requests.HTTPError as e:
                    # return render(request, "error.html", {
                    #     "error": "{0}".format(e),
                    # })
                    traceback.print_exc()

        elif request.POST["rl_token"]:
            rl_token = request.POST["rl_token"]
            if not rl_token:
                return render(request, "error.html",{
                    "error": "You must supply a ReversingLabs Token."
                })
            for rl_hash in request.POST["rl_hashes"].split():
                if not UsageLimits.take_credit(request.user):
                    break
                response = requests.get("https://a1000.reversinglabs.com/api/samples/"+rl_hash+"/download/", headers={"Authorization":"Token %s" % rl_token})

                try:
                    response.raise_for_status()
                    path = store_temp_file(response.content, rl_hash)
                    paths.append(path)
                except requests.HTTPError as e:
                   traceback.print_exc()

            if not paths:
                return render(request, "error.html", {
                    "error": "That hash may not be on ReversingLabs, or something may have gone wrong"
            })

        for path in paths:
            for entry in task_machines:
                task_id = db.add_path(file_path=path,
                                      package=package,
                                      timeout=timeout,
                                      options=emit_options(options),
                                      priority=priority,
                                      machine=entry,
                                      custom=custom,
                                      memory=memory,
                                      enforce_timeout=enforce_timeout,
                                      tags=tags,
                                      owner=request.user.username if request.user.is_authenticated else "",
                                      tlp=tlp)
                if task_id:
                    task_ids.append(task_id)

    # When submitting a dropped file.
    elif request.POST.get("category") == "dropped_file":
        filepath = dropped_filepath(task_id, sha1)

        for entry in task_machines:
            if not UsageLimits.take_credit(request.user):
                break
            task_id = db.add_path(file_path=filepath,
                                  package=package,
                                  timeout=timeout,
                                  options=emit_options(options),
                                  priority=priority,
                                  machine=entry,
                                  custom=custom,
                                  memory=memory,
                                  enforce_timeout=enforce_timeout,
                                  tags=tags,
                                  owner=request.user.username if request.user.is_authenticated else "",
                                  tlp=tlp)
            if task_id:
                task_ids.append(task_id)

    else:
        url = request.POST.get("url").strip()
        if not url:
            return render(request, "error.html", {
                "error": "You specified an invalid URL!",
            })

        for entry in task_machines:
            if not UsageLimits.take_credit(request.user):
                break
            task_id = db.add_url(url=url,
                                 package=package,
                                 timeout=timeout,
                                 options=emit_options(options),
                                 priority=priority,
                                 machine=entry,
                                 custom=custom,
                                 memory=memory,
                                 enforce_timeout=enforce_timeout,
                                 tags=tags,
                                 owner=request.user.username if request.user.is_authenticated else "",
                                 tlp=tlp)
            if task_id:
                task_ids.append(task_id)

    tasks_count = len(task_ids)
    if tasks_count > 0:
        return render(request, "submission/complete.html", {
            "tasks": task_ids,
            "tasks_count": tasks_count,
            "baseurl": request.build_absolute_uri('/')[:-1],
            "creditsleft": UsageLimits.get_credit(request.user)
        })
    else:
        return render(request, "error.html", {
            "error": "Error adding task to Cuckoo's database.",
        })


def get_task_machines(db, machine):
    task_machines = []
    if machine.lower() == "all":
        for entry in db.list_machines():
            task_machines.append(entry.label)
    else:
        task_machines.append(machine)
    return task_machines


@login_required
def status(request, task_id):
    task = db.view_task(task_id)
    if not task:
        return render(request, "error.html", {
            "error": "The specified task doesn't seem to exist.",
        })

    if task.status == "reported":
        return redirect("analysis.views.report", task_id=task_id)

    return render(request, "submission/status.html", {
        "status": task.status,
        "task_id": task_id,
    })


@login_required
def resubmit(request, task_id):
    task = db.view_task(task_id)

    if request.method == "POST":
        return index(request, task_id)

    if not task:
        return render(request, "error.html", {
            "error": "No Task found with this ID",
        })

    if task.category == "file":
        return render_index(request, {
            "sample_id": task.sample_id,
            "file_name": os.path.basename(task.target),
            "resubmit": "file",
            "options": emit_options(task.options),
        })
    elif task.category == "url":
        return render_index(request, {
            "url": task.target,
            "resubmit": "URL",
            "options": emit_options(task.options),
        })


@login_required
def submit_dropped(request, task_id, sha1):
    if request.method == "POST":
        return index(request, task_id, sha1)

    task = db.view_task(task_id)
    if not task:
        return render(request, "error.html", {
            "error": "No Task found with this ID",
        })

    filepath = dropped_filepath(task_id, sha1)
    return render_index(request, {
        "file_name": os.path.basename(filepath),
        "resubmit": "file",
        "dropped_file": True,
        "options": emit_options(task.options),
    })

def get_vpns():
    vpn = Config("vpn")
    vpns={}
    # Check whether all VPNs exist if configured and make their configuration
    # available through the vpns variable. Also enable NAT on each interface.
    if vpn.vpn.enabled:
        for name in vpn.vpn.vpns.split(","):
            name = name.strip()
            if not name:
                continue

            if not hasattr(vpn, name):
                logging.warn("Configuration not found for {0}".format(name))

            entry = vpn.get(name)
            vpns[entry.name] = entry
    return vpns
