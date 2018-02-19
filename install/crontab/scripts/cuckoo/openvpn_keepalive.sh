#!/bin/bash
CUCKOO_HOME="CUCKOODIR"
grep dev $CUCKOO_HOME/install/openvpn/*.conf|awk '{print $NF}'|sort -u|while read INT; do
    /sbin/ifconfig "$INT" |grep 'inet addr'|awk -F 'addr:' '{print $2}'|awk '{print $1}'|sed -r 's/[0-9]+$/1/g'|while read ip ; do
        ping -I $INT -nn -W 5 -i 120 -s 20 -p 4b6565702d416c697665 $ip >> "/var/log/cuckoo/ping.log" 2>&1 &
    done
done
