#!/bin/bash
## This line is dogshit
## set -e breaks stuff like adding a repo
## if it breaks, uncomment
#set -e
##
## Who the fsck is Joe Blow?!
## OMNIPOTENTLY IDEMPOTENT BASH SCRIPT >> THIS SCRIPT STOMPS ON EVERYTHING BUT ITSELF, INSTALL IT ON A FRESH SYSTEM OR CAVEAT EMPTOR!

if [[ ${EUID} -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi


edit_crontab() {
    cron_file=$1
    user=$2

    crontab -u ${user} -l 2> /dev/null > cuckoocron
    sed -i '/#CUCKOOCRONS/,/#ENDCUCKOOCRONS/d' cuckoocron
    /bin/cp -f ${cron_file} cuckoocron
    replace_templates "cuckoocron"
    crontab -u ${user} cuckoocron
    rm cuckoocron
}

replace_templates() {
    sed -i "s:CUCKOODIR:$(realpath ${CUCKOODIR}):g" $1
    sed -i "s/CUCKOO_USER/${CUCKOO_USER}/g" $1
    sed -i "s/SANDIP/${SANDIP}/g" $1
    sed -i "s/SANDINT/${SANDINT}/g" $1
    sed -i "s#MYSQL_CONN_STR#${MYSQL_CONN_STR}#g" $1
    sed -i "s/DOCKER_MONGO_IP/${DOCKER_MONGO_IP}/g" $1
    sed -i "s:DOCKER_MONGO_DIR:$(realpath ${DOCKER_MONGO_DIR}):g" $1
    sed -i "s#DOCKER_MONGO_NET#${DOCKER_MONGO_NET}#g" $1

    sed -i "s/DOCKER_MYSQL_DATABASE/${DOCKER_MYSQL_DATABASE}/g" $1
    sed -i "s/DOCKER_MYSQL_PASSWORD/${DOCKER_MYSQL_PASSWORD}/g" $1
    sed -i "s/DOCKER_MYSQL_IP/${DOCKER_MYSQL_IP}/g" $1
    sed -i "s/DOCKER_MYSQL_USER/${DOCKER_MYSQL_USER}/g" $1
    sed -i "s/DOCKER_MYSQL_ROOT_PASSWORD/${DOCKER_MYSQL_ROOT_PASSWORD}/g" $1
    sed -i "s:DOCKER_MYSQL_DIR:$(realpath ${DOCKER_MYSQL_DIR}):g" $1

    sed -i "s:DOCKER_ELASTIC_DIR:$(realpath ${DOCKER_ELASTIC_DIR}):g" $1
    sed -i "s/DOCKER_ELASTIC_IP/${DOCKER_ELASTIC_IP}/g" $1



}

# This is where the magic happens
## 
echo "Updating packages"
SURICHECK=$(dpkg -l|grep suricata)
if [ -z "$SURICHECK" ]; then
add-apt-repository -y ppa:oisf/suricata-stable
fi
apt-get update -y
apt-get upgrade -y

echo "Installing dependencies"

apt-get install -y fail2ban openvpn apache2 wget curl uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev iptables-persistent build-essential libssl-dev python-dev libxml2-dev libxslt-dev libtiff5-dev libjpeg8-dev zlib1g-dev libfreetype6-dev liblcms2-dev libwebp-dev tcl8.6-dev tk8.6-dev python-tk libmysqlclient-dev libpcre3-dbg libpcre3-dev autoconf automake libtool libpcap-dev libnet1-dev libyaml-dev zlib1g-dev libcap-ng-dev libmagic-dev libjansson-dev libjansson4 python-pip suricata yara htop nmon apparmor-utils tcpdump volatility mysql-client python python-yaml python-mysqldb python-psycopg2 nodejs lm-sensors netcat zlib1g-dev uuid-dev libmnl-dev gcc make autoconf autoconf-archive autogen automake pkg-config sysfsutils unzip

echo "Grabbing python packs"
pip install --upgrade pip
pip install -r ../requirements.txt

# The user you'll run cuckoo services as
CUCKOO_USER="cuckoo"
# email for....
EMAIL="default@beastmode.tools"
# VM network , used for detonations
SANDNET="10.200.0.0/24"
# IP For the physical host, on the virtual network.
# This will have to be the default gateway of the virtualbox machines you intend to use for detonations
SANDIP="10.200.0.254"
# The interface you want your VMs to be using to get to the internet
SANDINT="vboxnet0"
# MongoDB location details
# Right now we specifically use localhost to not expose anything externally, especially with docker and the DBs
# If you change the DBs to something other than localhost + docker, you'll probably want to run the install by hand
DOCKER_MONGO_IP="172.18.1.254"
DOCKER_MONGO_NET="172.18.1.0/24"
DOCKER_MONGO_DIR="/data/mongo"
# Elastic database details
DOCKER_ELASTIC_IP="172.18.1.253"
# See line  160 if you want to separate the networks
#DOCKER_ELASTIC_NET="172.18.2.0/24"
DOCKER_ELASTIC_DIR="/data/elastic"
# MySQL database details
DOCKER_MYSQL_IP="172.18.1.252"
DOCKER_MYSQL_PASSWORD="cuckoo"
DOCKER_MYSQL_DIR="/data/mysql"
DOCKER_MYSQL_DATABASE="cuckoo"
DOCKER_MYSQL_ROOT_PASSWORD="Root123"
MOLOCH_USER="admin"
MOLOCH_PASSWORD="admin"
MYSQL_CONN_STR="mysql://${CUCKOO_USER}:${DOCKER_MYSQL_PASSWORD}@${DOCKER_MYSQL_IP}/${DOCKER_MYSQL_DATABASE}"
# Openvpn configuration location.  This will have to match with systemd or whatever you use
OPENVPN="/etc/openvpn"
CUCKOODIR=".."
#I know this is greasy, but requires no interaction
MOLOCHS2SPW=$(date|sha256sum|awk '{ print $1 }')

## If you have a big data slice, put your storage mount in there
#CUCKOOSTORAGE="/storage"
#if [ -n "$CUCKOOSTORAGE" ]; then
#    mv "$CUCKOODIR/storage/*" "$CUCKOOSTORAGE/" && rmdir "$CUCKOODIR/storage"  && ln -s "$CUCKOOSTORAGE" "$CUCKOODIR/storage" && chown -R $CUCKOO_USER.$CUCKOO_USER "$CUCKOOSTORAGE" "$CUCKOODIR/storage"
#fi

### EDIT PAST THIS AT YOUR PERIL

# Get creative with your symlinks!!!
#if [ -z $(grep "$CUCKOOMEMORY" /etc/fstab) ]; then
#    echo "tmpfs       $CUCKOODIR/storage/memory tmpfs   nodev,nosuid,noexec,nodiratime,size=$CUCKOOMEMORYSIZE   0 0" >> /etc/fstab
#    mkdir -p "$CUCKOODIR/storage/memory"
#    mount -a
#fi
## Disable hugepage for better mongo performance
if [ -z $(grep 'kernel/mm/transparent_hugepage/enabled = never' /etc/sysfs.conf) ]; then
	echo -e 'kernel/mm/transparent_hugepage/enabled = never\nkernel/mm/transparent_hugepage/defrag = never' >> /etc/sysfs.conf
	echo 'never' > /sys/kernel/mm/transparent_hugepage/enabled
	echo 'never' > /sys/kernel/mm/transparent_hugepage/defrag
fi

#Docker won't install if openvpn is running with VPNs.  Shutting it off to avoid issues
service openvpn stop
# Check if docker is installed, if not install it
DOCKERCHECK=$(dpkg -l|grep docker-ce)
if [ -z "$DOCKERCHECK" ]; then
echo "Installing Docker-CE"
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository \
   "deb [arch=amd64] https://download.docker.com/linux/ubuntu \
   $(lsb_release -cs) \
   stable"
apt-get update -y
apt-get install -y docker-ce
curl -L https://github.com/docker/compose/releases/download/1.19.0/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
fi

## Docker containers for DBs is probably a bad idea, don't use this for prod deployments
echo "Setting up Docker networks and containers if they don't already exist"
mkdir -p "${DOCKER_MONGO_DIR}/db"
mkdir -p "${DOCKER_MONGO_DIR}/etc"
mkdir -p "${DOCKER_ELASTIC_DIR}"
chown 1000.1000 ${DOCKER_ELASTIC_DIR}
/bin/cp -f "mongodb/mongod.conf" "${DOCKER_MONGO_DIR}/etc"

# You could put these on a network if you want to later
# [ ! "$(docker network ls | grep mongo)" ] && docker network create --subnet=${DOCKER_MONGO_NET} mongo
# Right now we're putting all the docker containers in the same network, but you can separate that out if you'd like
#[ ! "$(docker network ls | grep es)" ] && docker network create --subnet=${DOCKER_ELASTIC_NET} es
# check if docker images have already been created, if not it creates them
#sudo [ ! "$(docker ps -a | grep cuckoo-mongo)" ] && docker run --restart always -d --name cuckoo-mongo --net mongo --ip ${DOCKER_MONGO_IP} -p 27017 -v ${DOCKER_MONGO_DIR}/db:/data/db -v ${DOCKER_MONGO_DIR}/etc/mongod.conf:/etc/mongod.conf mongo
#sudo [ ! "$(docker ps -a | grep cuckoo-elastic)" ] && docker run --restart always -d --name cuckoo-elastic --net mongo --ip ${DOCKER_ELASTIC_IP} -p 9200 -p 9300 -v ${DOCKER_ELASTIC_DIR}:/data/elastic -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:5.6.6
#sudo [ ! "$(docker ps -a | grep cuckoo-mysql)" ] && docker run --restart always -d --name cuckoo-mysql --net mongo --ip ${DOCKER_MYSQL_IP} -p 3306 -e MYSQL_USER=${CUCKOO_USER} -e MYSQL_PASSWORD=${DOCKER_MYSQL_PASSWORD} -e MYSQL_DATABASE=${DOCKER_MYSQL_DATABASE} -e MYSQL_ROOT_PASSWORD=${DOCKER_MYSQL_ROOT_PASSWORD} -v ${DOCKER_MYSQL_DIR}:/data/mysql  mysql:5.7

#sudo [ ! "$(docker ps -a | grep cuckoo-mongo)" ] && docker run --restart always -d --name cuckoo-mongo -p ${DOCKER_MONGO_IP}:27017:27017 -v ${DOCKER_MONGO_DIR}/db:/data/db -v ${DOCKER_MONGO_DIR}/etc/mongod.conf:/etc/mongod.conf mongo
#sudo [ ! "$(docker ps -a | grep cuckoo-elastic)" ] && docker run --restart always -d --name cuckoo-elastic -p ${DOCKER_ELASTIC_IP}:9200:9200 -p ${DOCKER_ELASTIC_IP}:9300:9300 -v ${DOCKER_ELASTIC_DIR}:/data/elastic -e "discovery.type=single-node" -e "xpack.security.enabled=false" docker.elastic.co/elasticsearch/elasticsearch:5.6.6
#sudo [ ! "$(docker ps -a | grep cuckoo-mysql)" ] && docker run --restart always -d --name cuckoo-mysql -p ${DOCKER_MYSQL_IP}:3306:3306 -e MYSQL_USER=${CUCKOO_USER} -e MYSQL_PASSWORD=${DOCKER_MYSQL_PASSWORD} -e MYSQL_DATABASE=${DOCKER_MYSQL_DATABASE} -e MYSQL_ROOT_PASSWORD=${DOCKER_MYSQL_ROOT_PASSWORD} -v ${DOCKER_MYSQL_DIR}:/data/mysql  mysql:5.7

/bin/cp -f docker/docker-compose.yml ../docker/
replace_templates "../docker/docker-compose.yml"
docker-compose  -f ../docker/docker-compose.yml up -d

# waiting for ES to come up
sleep 5


# Setup iptables

if [ -z $(iptables -nL|grep 'IPTABLES-INPUT-CHAIN') ]; then
service netfilter-persistent start
iptables -I INPUT -i vboxnet0 -p tcp -m state --state NEW -m tcp --dport 2042 -j ACCEPT
iptables -I INPUT -s 127.0.0.1 -d 127.0.0.1 -p tcp -m state --state NEW -m tcp --dport 8090 -j ACCEPT
iptables -I INPUT -s 127.0.0.1 -d 127.0.0.1 -p tcp -m state --state NEW -m tcp --dport 8000 -j ACCEPT
iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 8005 -j ACCEPT
iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 22 -j ACCEPT
iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 80 -j ACCEPT
iptables -I INPUT -p tcp -m state --state NEW -m tcp --dport 443 -j ACCEPT
iptables -I INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT -m limit --limit 1/sec -j LOG --log-prefix "IPTABLES-INPUT-CHAIN-TOP|" --log-level 7
iptables -A INPUT -m limit --limit 1/sec -j LOG --log-prefix "IPTABLES-INPUT-CHAIN-DROPPED|" --log-level 7
iptables -A INPUT -j DROP
## Even... more... grease...
## This stops the DBs from listening on external interfaces
grep iface /etc/network/interfaces|grep -v 'lo'|awk '{print $2}'|while read myint; do
for i in 9200 9300 3306 27017; do
	iptables -I FORWARD -i "$myint" -p tcp -m state --state NEW -m tcp --dport "$i" -j DROP
done
done
## Only allow your docker bridge interfaces to hit the DBs
iptables -I FORWARD ! -s $DOCKER_MONGO_NET -p tcp -m tcp --dport 3306 -j DROP
iptables -I FORWARD ! -s $DOCKER_MONGO_NET -p tcp -m tcp --dport 9200 -j DROP
iptables -I FORWARD ! -s $DOCKER_MONGO_NET -p tcp -m tcp --dport 9300 -j DROP
iptables -I FORWARD ! -s $DOCKER_MONGO_NET -p tcp -m tcp --dport 27017 -j DROP

iptables -I FORWARD -m limit --limit 1/sec -j LOG --log-prefix "IPTABLES-FORWARD-CHAIN-TOP|" --log-level 7
iptables -A FORWARD -m limit --limit 1/sec -j LOG --log-prefix "IPTABLES-FORWARD-CHAIN-DROPPED|" --log-level 7
iptables -A FORWARD -j DROP


invoke-rc.d netfilter-persistent save
fi

## Get virtualbox
VBOXCHECK=$(dpkg -l|grep virtualbox-5.2)
if [ -z "$VBOXCHECK" ]; then
echo "Installing VirtualBox"
echo 'deb http://download.virtualbox.org/virtualbox/debian xenial contrib' >> /etc/apt/sources.list
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
sudo apt-get update -y
sudo apt-get install -y virtualbox-5.2
wget "https://download.virtualbox.org/virtualbox/5.2.6/Oracle_VM_VirtualBox_Extension_Pack-5.2.6-120293.vbox-extpack"
vboxmanage extpack install Oracle_VM_VirtualBox_Extension_Pack-5.2.6-120293.vbox-extpack

fi

# Setup the VM network, where your host will act as a default gateway for the guest VMs
VMINTCHECK=$(ifconfig -a|grep ${SANDINT})
if [ -z ${VMINTCHECK} ]; then
echo "Adding host interface"
vboxmanage hostonlyif create
# If you set the IP for your SANDINT as root, then every time your box runs 'vboxheadless' your vboxnet0 IP will revert back to 192.168.56.1
## Many, many hours lost here
su - $CUCKOO_USER -c "vboxmanage hostonlyif ipconfig $SANDINT --ip $SANDIP --netmask 255.255.255.0"
fi


# #BUG - This didn't work sed-fu no good
cp /etc/rc.local temp.local
sed -i '/#CUCKOOLOCALS/,/#ENDCUCKOOLOCALS/d' temp.local
cat rc.local_template >> temp.local
replace_templates "temp.local"
/bin/cp -f temp.local /etc/rc.local
sed -i 's/exit 0//g' /etc/rc.local

id -u ${CUCKOO_USER}
if [ $? -eq 1 ]; then
echo "==== Adding local *NIX user to run Phoenix - ${CUCKOO_USER}"+${CUCKOO_USER}
adduser "${CUCKOO_USER}"
fi

chown -R "${CUCKOO_USER}.${CUCKOO_USER}" "${CUCKOODIR}"



#Fail2Ban
echo "Setting Fail2Ban to drop"
sed -i 's/blocktype =.*/blocktype = DROP/g' /etc/fail2ban/action.d/iptables-common.conf

# It's certificate time
if [ ! -f /etc/pki/tls/private/$HOSTNAME.key ]; then
echo "Setting up certificates"
openssl genrsa -out ca.key 8192



# Generate CSR 
openssl req -new -key ca.key -out ca.csr

# Generate Self Signed Key
openssl x509 -req -days 365 -in ca.csr -signkey ca.key -out ca.crt

# Copy the files to the correct locations
mkdir -p /etc/pki/tls/certs
mkdir -p /etc/pki/tls/private

cp ca.crt /etc/pki/tls/certs
cp ca.key /etc/pki/tls/private/$HOSTNAME.key
cp ca.csr /etc/pki/tls/private/$HOSTNAME.csr
fi

## #TODO this is not tested yet
# If you use our configuration you have to maintain your backend cuckooweb port in httpd/cuckoo.conf
# Default is 127.0.0.1:8000
echo "Setting up HTTPD"
/bin/cp -f httpd/cuckoo.conf /etc/apache2/conf-enabled/
sed -i "s/EMAIL_REPLACE/${EMAIL}/g" /etc/apache2/conf-enabled/cuckoo.conf
sed -i "s/HOSTNAME_REPLACE/${HOSTNAME}/g" /etc/apache2/conf-enabled/cuckoo.conf
## Disable standard http
sed -i "s/Listen 80/#Listen 80/g" /etc/apache2/ports.conf
mkdir -p /var/log/apache2/cuckoo
sudo a2enmod rewrite
service apache2 restart
#cp httpd/cuckoo.conf /etc/httpd/conf.d/



echo "Adding elasticsearch hunt template"
ESTEMPLATECHECK=$(curl ${DOCKER_ELASTIC_IP}:9200/_template/hunt 2>/dev/null|grep '\"template\":\"hunt-\*\"')
if [ -z "${ESTEMPLATECHECK}" ]; then
    curl -XPUT "${DOCKER_ELASTIC_IP}:9200/_template/hunt" -d "$(cat docker/elastic/elastic.template)"
fi


echo "Adding init.d scripts to start cuckoo at system start"
cp init.d/* /etc/init.d/


# Download and install moloch
MOLOCHCHECK=$(dpkg -l|grep moloch)
if [ -z "$MOLOCHCHECK" ]; then
echo "Downloading Moloch"
wget "https://files.molo.ch/builds/ubuntu-16.04/moloch_0.50.0-1_amd64.deb"
dpkg -i moloch_0.50.0-1_amd64.deb

## Install certificates
/data/moloch/bin/Configure
/bin/cp -f moloch/config.ini /data/moloch/etc/config.ini
/bin/cp -f /etc/pki/tls/private/$HOSTNAME.key /data/moloch/etc/c.key
/bin/cp -f /etc/pki/tls/certs/ca.crt /data/moloch/etc/c.crt
/bin/cp -f moloch/viewer.js /data/moloch/viewer/viewer.js

replace_templates "/data/moloch/etc/config.ini"
#TODO - degrease this...
sed -i "s/REPLACE_MOLOCH_PASSWORD/${MOLOCHS2SPW}/g" /data/moloch/etc/config.ini
sed -i 's/# certFile.*/certFile=\/data\/moloch\/etc\/c.crt/g' /data/moloch/etc/config.ini
sed -i 's/# keyFile.*/keyFile=\/data\/moloch\/etc\/c.key/g' /data/moloch/etc/config.ini
sed -i 's/\[default\]/\[default\]\nreadTruncatedPackets = true/g' /data/moloch/etc/config.ini
# Initialize moloch ES db & update geo
perl /data/moloch/db/db.pl ${DOCKER_ELASTIC_IP}:9200 init
/data/moloch/bin/moloch_add_user.sh ${MOLOCH_USER} "Admin User" ${MOLOCH_PASSWORD} --admin

#Grease...Grease everywhere
LOCALDIR=$PWD
cd /data/moloch/viewer
../bin/node ../bin/npm install request
../bin/node ../bin/npm install sync-promise
cd $LOCALDIR
fi



# Replace initd scripts with build details
replace_templates "/etc/init.d/cuckoo*"

echo "Pushing cuckoo conf files"
/bin/cp -rf ${CUCKOODIR}/install/conf/* ${CUCKOODIR}/conf
replace_templates "${CUCKOODIR}/conf/*"

echo "Installing OVAs"
chmod +x cuckoo_install_vms.sh
/bin/cp -pf cuckoo_install_vms.sh /home/$CUCKOO_USER/
## This doesn't gracefully copy stuff, it overwrites, consumes time
echo "=== Copying files to staging virtualbox template folder ==="
echo "=== This might take awhile =="

# Check if you've got VMs installed, if you do, don't install anything
INSTALLEDVMS=$(su - cuckoo -c "vboxmanage list vms"|awk '{print $1}'|sed 's/"//g'|tr '\n' ','|sed 's/.$//g')
if [ -z "$INSTALLEDVMS" ]; then

/bin/cp -pnr virtualbox/ /home/$CUCKOO_USER/vbox_templates/
su - $CUCKOO_USER -c "/home/$CUCKOO_USER/cuckoo_install_vms.sh $(realpath ${CUCKOODIR}/conf/virtualbox.conf) $SANDINT $SANDIP"
INSTALLEDVMS=$(su - cuckoo -c "vboxmanage list vms"|awk '{print $1}'|sed 's/"//g'|tr '\n' ','|sed 's/.$//g')
sed -i "s/machines = .*/machines = $INSTALLEDVMS/g" $CUCKOODIR/conf/virtualbox.conf
else
echo "Not copying any VMs, because you already have some"
fi
#TODO Idempotently add/replace virtualbox/limits.conf_template lines to /etc/security/limits.conf

echo "Editing Crontab"
/bin/cp -rf ${CUCKOODIR}/install/crontab/scripts/ ${CUCKOODIR}/utils/crontab/
chmod +x ${CUCKOODIR}/utils/crontab/*/*.sh
# Replacing variables in crontab files for both users
for file in  $(find ${CUCKOODIR}/utils/crontab/*|grep sh); do
    replace_templates "${file}"
done
# Ensuring cuckoo can't put jobs in root's cron
chown -R root.root ${CUCKOODIR}/utils/crontab/root
#More templating and adding crons


edit_crontab "crontab/crontab_root.template" "root"
edit_crontab "crontab/crontab.template" "${CUCKOO_USER}"

# Copy openvpn configs to openvpn folder
# if you don't already have your openvpn configs deployed, do that
if ! ls "${OPENVPN}/*.conf" >> /dev/null; then
    echo "Copying OpenVPN configs"
    cp openvpn/* "${OPENVPN}"/
    update-rc.d openvpn defaults
    echo -e "[vpn]\nenabled = yes\n" > $CUCKOODIR/conf/vpn.conf
    echo "vpns = $(ls openvpn/*.conf|sed 's/\.conf//g'|tr '\n' ','|sed 's/openvpn\///g'|sed 's/.$//g')" >> $CUCKOODIR/conf/vpn.conf
    VPNARRAY=$(grep dev openvpn/*.conf|awk '{print $NF}'|tr '\n' ' '|sed 's/.$//g')
    sed -i "s/REPLACEVPNS/\"$VPNARRAY\"/g" "$CUCKOODIR/utils/crontab/root/openvpn_route.sh"
    echo '#
# reserved values
#
255     local
254     main
253     default
0       unspec' > /etc/iproute2/rt_tables
    VPNCOUNTER=2
    ls openvpn/*.conf|while read vpnfile; do
        VPNNAME=$(echo $vpnfile|sed 's/\.conf//g'|sed 's/openvpn\///g')
        VPNDEV=$(grep dev $vpnfile|awk '{print $NF}')
        # Assign your VPN adapter to cuckoo's VPN config file
        echo "[${VPNNAME}]" >> $CUCKOODIR/conf/vpn.conf
        echo "name = ${VPNNAME}" >> $CUCKOODIR/conf/vpn.conf
        echo "description = ${VPNNAME}" >> $CUCKOODIR/conf/vpn.conf
        echo "interface = ${VPNDEV}" >> $CUCKOODIR/conf/vpn.conf
        echo "rt_table = ${VPNDEV}" >> $CUCKOODIR/conf/vpn.conf
        # Build your routing table files for iproute2
        echo "$VPNCOUNTER   ${VPNDEV}" >> /etc/iproute2/rt_tables
        VPNCOUNTER=$((VPNCOUNTER + 1))
    done
fi

# Start up openvpn
service openvpn start
echo "Waiting for openvpn tunnels to be up for sure... a lot of stuff that follows is dependent on it (cuckooweb, cuckoorooter, cuckood, etc."
sleep 30
#TODO remove /etc/init.d/functions from init.d scripts
touch /etc/init.d/functions
echo "Starting cuckooRooter"
service cuckoorooter start
sleep 10


# Make logging dir
echo "Adding cuckoo logging folder"
mkdir -p /var/log/cuckoo
chown $CUCKOO_USER.$CUCKOO_USER /var/log/cuckoo

echo "Update cuckoo bins and sigs"
python ../utils/community.py -waf
echo "Done!"

echo "Update cuckoo web db"
service cuckoorooter restart
python ../web/manage.py migrate

#TODO how can this be checked?
echo "Create Django superuser"
python ../web/manage.py createsuperuser

echo "Initialize Yara rules"
if [ ! -d "${CUCKOODIR}/data/yara/rules/external" ];then
    mkdir -p "${CUCKOODIR}/data/yara/rules/external"
    git clone https://github.com/Yara-Rules/rules.git ${CUCKOODIR}/data/yara/rules/external
else
    git -C ${CUCKOODIR}/data/yara/rules/external pull
fi
#/bin/cp -ru ${CUCKOODIR}/data/yara/rules/external ${CUCKOODIR}/data/yara/memory
#/bin/cp -ru ${CUCKOODIR}/data/yara/rules/external ${CUCKOODIR}/data/yara/binaries
#
#rm -f ${CUCKOODIR}/data/yara/memory/*_index.yar
#rm -f ${CUCKOODIR}/data/yara/memory/index_w_mobile.yar
#rm -f ${CUCKOODIR}/data/yara/memory/malware/MIRAI*.yar
#rm -f ${CUCKOODIR}/data/yara/memory/malware/*ELF*.yar
#sed -i 's/*ELF*//g'${CUCKOODIR}/data/yara/memory/index.yar
#sed -i 's/*MIRAI*//g'${CUCKOODIR}/data/yara/memory/index.yar
#
#rm -f ${CUCKOODIR}/data/yara/binaries/*_index.yar
#rm -f ${CUCKOODIR}/data/yara/binaries/index_w_mobile.yar
#rm -f ${CUCKOODIR}/data/yara/binaries/malware/MIRAI*.yar
#rm -f ${CUCKOODIR}/data/yara/binaries/malware/*ELF*.yar
#sed -i 's/*ELF*//g'${CUCKOODIR}/data/yara/binaries/index.yar
#sed -i 's/*MIRAI*//g'${CUCKOODIR}/data/yara/binaries/index.yar



chown -R $CUCKOO_USER.$CUCKOO_USER ${CUCKOODIR}/data/yara


echo "Starting services"
service molochviewer start
#aa-disable /usr/sbin/tcpdump
setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump
#../utils/crontab/cuckoo_full_restart.sh

# Add cuckoo user to docker group
if [ -z $(getent group docker|grep $CUCKOO_USER) ]; then
    usermod -aG docker $CUCKOO_USER
fi

#Build the hunting containers
if [ -z $(docker ps -a|grep prodyara) ]; then
    mkdir -p $CUCKOODIR/docker/yara  && docker build -t prodyara $CUCKOODIR/docker/yara
fi
if [ -z $(docker ps -a|grep prodsuri) ]; then
    mkdir -p $CUCKOODIR/docker/suricata  && docker build -t prodsuricata $CUCKOODIR/docker/suricata
fi

## Install netdata
echo "Installing netdata for system monitoring"

git clone https://github.com/firehol/netdata.git --depth=1 /opt/netdata
LOCALDIR=$PWD
cd /opt/netdata
/opt/netdata/netdata-installer.sh
sed -i 's/.*# bind to = .*/\tbind to = 127.0.0.1/g' /etc/netdata/netdata.conf
systemctl enable netdata
service netdata restart
cd ${LOCALDIR}

echo "Done!"
echo "Now go and setup your VMs to have snapshots and you're good to go!  #TODO - figure out how to migrate virtualboxes with pre-existing snapshots
This might be a good start:
###  vboxmanage modifyvm win7-x86-0 --vrde on
###  vboxmanage modifyvm win7-x86-0 --vrdeaddress 127.0.0.1
###  vboxmanage modifyvm win7-x86-0 --vrdeport 3389
###  vboxheadless -v on -e authType=NULL -s win7-x86-0
# on a different shell do this
###  vboxmanage snapshot win7-x86-0 take clean
# Once you've taken your snapshots and your virtualbox.conf is configured properly (ports AND IPs match up with your VMs) You're good to start cuckoo:
### /opt/phoenix/utils/crontab/root/cuckoo_full_restart.sh
###  vboxheadless -v on -e TCP/Ports=$XRDPPort -e TCP/Address=$XRDP -e authType=NULL -s \$VMNAME
#####  get your box listening with cuckoo agent then run this:
###  vboxmanage snapshot \$VMNAME take clean"

# This takes us to POST image creation
# Import existing images and use them to continue

