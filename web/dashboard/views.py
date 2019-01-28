# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import sys
import time

from django.conf import settings
from django.shortcuts import render
from django.views.decorators.http import require_safe
from pymisp import PyMISP

from lib.cuckoo.common.config import Config

config = Config("reporting")
options = config.get("z_misp")
sys.path.insert(0, settings.CUCKOO_PATH)

from lib.cuckoo.core.database import Database, TASK_PENDING, TASK_RUNNING
from lib.cuckoo.core.database import TASK_COMPLETED, TASK_RECOVERED, TASK_REPORTED
from lib.cuckoo.core.database import TASK_FAILED_ANALYSIS, TASK_FAILED_PROCESSING, TASK_FAILED_REPORTING
from django.contrib.auth.decorators import login_required
db = Database()

@require_safe
@login_required
def index(request):

    misp_url = options["url"]

    if ":" in request.get_host():
        hostname = request.get_host().split(":")[0]
    else:
        hostname = request.get_host()
    if settings.MOLOCH_INSECURE:
        moloch_url = "http://"
    else:
        moloch_url = "https://"

    moloch_url += "%s%s" % (
        settings.MOLOCH_HOST or hostname,
        ":" + settings.MOLOCH_PORT if settings.MOLOCH_PORT else "")

    misp = PyMISP(misp_url, options["apikey"], False)
    resp = misp.get_all_tags()
    tags=[]
    if resp and "Tag" in resp:
        tags = sorted(filter(lambda tag: tag["count"] > 0, resp["Tag"]), key=lambda tag: tag["count"], reverse=True)
    report = dict(
        total_samples=db.count_samples(),
        total_tasks=db.count_tasks(),
        all_time_tasks = db.count_tasks(hours=None),
        all_time_reported = db.count_tasks(hours=None, status=TASK_REPORTED),
        states_count={},
        estimate_hour=None,
        estimate_day=None
    )

    states = (
        TASK_PENDING,
        TASK_RUNNING,
        TASK_COMPLETED,
        TASK_RECOVERED,
        TASK_REPORTED,
        TASK_FAILED_ANALYSIS,
        TASK_FAILED_PROCESSING,
        TASK_FAILED_REPORTING
    )

    for state in states:
        if state == TASK_RUNNING:
            report["states_count"][state] = db.count_tasks(state,None)
        else:
            report["states_count"][state] = db.count_tasks(state)

    offset = None

    # For the following stats we're only interested in completed tasks.
    tasks = db.count_tasks(status=TASK_COMPLETED)
    tasks += db.count_tasks(status=TASK_REPORTED)

    if tasks:
        # Get the time when the first task started and last one ended.
        started, completed = db.minmax_tasks()

        # It has happened that for unknown reasons completed and started were
        # equal in which case an exception is thrown, avoid this.
        if completed and started and int(completed - started):
            hourly = tasks / 24
        else:
            hourly = 0

        report["estimate_hour"] = int(hourly)
        report["estimate_day"] = int(24 * hourly)

    return render(request, "dashboard/index.html", {
        "report": report,
        "tags":tags,
        "misp_external_url": options["external_url"],
        "moloch_external_url": moloch_url
    })
