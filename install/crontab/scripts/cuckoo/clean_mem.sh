#!/bin/bash
find CUCKOODIR/storage/analyses/*/memory.dmp -mmin +359|while read line; do rm -f "$line"; done
MEMDUMPDIR=$(grep '^memdump_tmp' CUCKOODIR/conf/memory.conf |awk -F '=' '{print $2}'|sed 's/^ //g')
if [ -n "$MEMDUMPDIR" ]; then
    find $MEMDUMPDIR/*.dmp -amin +3|while read line; do rm -f $line;done
fi
find /tmp/cuckoo-tmp/ -amin +5|while read line; do rm -f $line;done