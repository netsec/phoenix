#!/bin/bash
MYDATE=$(date -u +%Y-%m-%dT%H:%M:%S.000'Z')
UUID=$(uuidgen)
UUID1=$(uuidgen)
ES="$1"
MONGOS="$2"
TODAY=$(date +%Y%m%d)
INDEX="mongostats-"
MSTATS=$(mongo $MONGOS/cuckoo --eval 'JSON.stringify(db.serverStatus())' | tail -n +3 | sed 's/\(NumberLong([[:punct:]]\?\)\([[:digit:]]*\)\([[:punct:]]\?)\)/\2/' | sed 's/\(ISODate(\)\(.*\)\()\)/\2/'|sed -e 's/^MongoDB server version: 3.6.2//g')
MSTATS1=$(mongo $MONGOS/cuckoo --eval 'JSON.stringify(db.stats())' | tail -n +3 | sed 's/\(NumberLong([[:punct:]]\?\)\([[:digit:]]*\)\([[:punct:]]\?)\)/\2/' | sed 's/\(ISODate(\)\(.*\)\()\)/\2/'|sed -e 's/^MongoDB server version: 3.6.2//g' -e "s/^{/{\"localTime\":\"$MYDATE\",/")
#echo $MSTATS
#echo $MSTATS1
curl -H "Content-Type: application/json" -XPUT "${ES}/${INDEX}${TODAY}/stats/$UUID" -d "$MSTATS" >/dev/null 2>&1
curl -H "Content-Type: application/json" -XPUT "${ES}/${INDEX}${TODAY}/stats/$UUID1" -d "$MSTATS1" >/dev/null 2>&1

