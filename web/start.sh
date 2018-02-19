#!/bin/bash
python2.7 manage.py runserver 0.0.0.0:8800 >> /tmp/greg.web 2>> /tmp/greg.web.error  &
