#!/usr/bin/env bash
SRC_HOME=$(mktemp -d)
CUCKOO_HOME=$PWD
LOCALDIR=$PWD
NOW=$(date +%Y%m%d_%H%M%S)
cp $CUCKOO_HOME/install/ubuntu_install.sh $CUCKOO_HOME/install/ubuntu_install.sh.$NOW
git clone https://github.com/SparkITSolutions/phoenix.git $SRC_HOME

rsync -ravhu --exclude 'conf' --exclude '.git*' --exclude '*settings.py' --exclude 'storage' --exclude 'install' $SRC_HOME/* $CUCKOO_HOME/
cd $CUCKOO_HOME/docker/yara
docker build -t prodyara .
cd $CUCKOO_HOME/docker/suricata
docker build -t prodsuricata .
chown -R cuckoo.cuckoo $CUCKOO_HOME
rm -rf $SRC_HOME
cd $CUCKOO_HOME/web
pip install -r ../requirements.txt

python manage.py makemigrations auth
python manage.py migrate auth

python manage.py makemigrations analysis
python manage.py migrate
