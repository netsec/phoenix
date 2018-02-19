#!/usr/bin/env bash
SRC_HOME=$(mktemp -d)
CUCKOO_HOME="."
LOCALDIR=$PWD
git clone https://github.com/SparkITSolutions/cuckoo $SRC_HOME
cd "$SRC_HOME" && git pull
rsync -ravhu --exclude 'conf' --exclude '.git*' --exclude '*settings.py' $SRC_HOME/* $CUCKOO_HOME/
cd $CUCKOO_HOME/docker/yara
docker build -t prodyara .
cd $CUCKOO_HOME/docker/suricata
docker build -t prodsuricata .
chown -R cuckoo.cuckoo /opt/phoenix
rm -rf $SRC_HOME
cd LOCALDIR