# Copyright (C) 2010-2013 Claudio Guarnieri.
# Copyright (C) 2014-2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file "docs/LICENSE" for copying permission.

from django.conf.urls import url

from . import views

urlpatterns = [
    url(r"^$", views.index),
    url(r"^submit/$", views.submit),
    url(r"^pcap/(?P<analysis_id>.+)/$", views.pcap),
    url(r"^(?P<task_id>.+)/$", views.report),
    url(r"^status/(?P<task_id>.+)$", views.status),
    url(r"^yara_file/(?P<hunt_uuid>.+)$", views.yara_file),
    url(r"^suri_file/(?P<hunt_uuid>.+)$", views.suri_file)
]
