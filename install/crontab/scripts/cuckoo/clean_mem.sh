#!/bin/bash
find CUCKOODIR/storage/analyses/*/memory.dmp -mmin +359|while read line; do rm -f "$line"; done
