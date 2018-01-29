#!/bin/bash
if [[ ${EUID} -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

edit_crontab() {
    cron_lines = $1
    user  = $2

    crontab -u ${user} -l 2> /dev/null > cuckoocron
    sed -i '/#CUCKOOCRONS/,/#ENDCUCKOOCRONS/d' cuckoocron
    echo ${cron_lines} >> cuckoocron
    replace_templates cuckoocron
    crontab -u ${user} cuckoocron
    rm cuckoocron
}

replace_templates() {
    sed -i "s/CUCKOODIR/${CUCKOODIR}/g" $1
    sed -i "s/CUCKOO_USER/${CUCKOO_USER}/g" $1
}

# This is where the magic happens
## 
echo "Updating packages"
apt-get update
apt-get upgrade

echo "Installing dependencies"
apt-get install docker fail2ban openvpn apache2 wget curl libpcre3-dev uuid-dev libmagic-dev pkg-config g++ flex bison zlib1g-dev libffi-dev gettext libgeoip-dev make libjson-perl libbz2-dev libwww-perl libpng-dev xz-utils libffi-dev iptables-persistent

EMAIL="default@beastmode.tools"
SANDNET="10.100.10.0/24"
SANDIP="10.100.10.254"
SANDINT="vboxnet0"
DOCKER_MONGO_IP="172.18.1.254"
DOCKER_MONGO_NET="172.18.1.0/24"
DOCKER_MONGO_DIR="/data/mongo"
DOCKER_ELASTIC_IP="172.18.2.254"
DOCKER_ELASTIC_NET="172.18.2.0/24"
DOCKER_ELASTIC_DIR="/data/elastic"
OPENVPN="/etc/openvpn"
CUCKOODIR="../"
CUCKOO_USER="cuckoo"

# Setup iptables
cp iptables/iptables /etc/iptables/rules.v4
sed -i 's/SANDNET/${SANDNET}/g' /etc/iptables/rules.v4
service netfilter-persistent start
invoke-rc.d netfilter-persistent save


# Copy openvpn configs to openvpn folder
#TODO: Do we always want to overwrite?  Check first maybe?
echo "Copying OpenVPN configs"
cp openvpn/* "${OPENVPN}"/
echo -e "[vpn]\nenabled = yes\n" > $CUCKOODIR/conf/vpn.conf
echo "vpns $(ls openvpn/*.conf|sed 's/\.conf//g'|tr '\n' ','|sed 's/openvpn\///g'|sed 's/.$//g')" >> $CUCKOODIR/conf/vpn.conf
ls openvpn/*.conf|while read vpnfile; do
    VPNNAME=$(echo $vpnfile|sed 's/\.conf//g'|sed 's/openvpn\///g')
    VPNDEV=$(grep dev $vpnfile|awk '{print $NF}')
    echo "[${VPNNAME}]" >> $CUCKOODIR/conf/vpn.conf
    echo "name = ${VPNNAME}" >> $CUCKOODIR/conf/vpn.conf
    echo "description = ${VPNNAME}" >> $CUCKOODIR/conf/vpn.conf
    echo "interface = ${VPNDEV}" >> $CUCKOODIR/conf/vpn.conf
    echo "rt_table = ${VPNDEV}" >> $CUCKOODIR/conf/vpn.conf
done
service openvpn stop
service openvpn start




## Get virtualbox
dpkg-query -l virtualbox-5.2 | grep -r "^ii" 2>&1 > /dev/null
if [ $? -eq  1 ]; then
echo "Installing VirtualBox"
echo 'deb http://download.virtualbox.org/virtualbox/debian xenial contrib' >> /etc/apt/sources.list
wget -q https://www.virtualbox.org/download/oracle_vbox_2016.asc -O- | sudo apt-key add -
wget -q https://www.virtualbox.org/download/oracle_vbox.asc -O- | sudo apt-key add -
sudo apt-get update
sudo apt-get install virtualbox-5.2
fi

#TODO: check for existing IF and remove first
echo "Adding host interface"
vboxmanage hostonlyif remove vboxnet0 2> /dev/null
vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig ${SANDINT} --ip "${SANDIP}" --netmask 255.255.255.0
echo "vboxmanage hostonlyif ipconfig ${SANDINT} --ip "${SANDIP}" --netmask 255.255.255.0" >> /etc/rc.local

# install ovas
ls virtualbox/*.ova|while read newvm; do
    VMNAME=$(echo $newvm|sed 's/\.ova//g')
    INSTALL_ABSOLUTE=$(realpath $PWD)
    su - $CUCKOO_USER -c "vboxmanage import ${INSTALL_ABSOLUTE}${newvm}"
    echo -e "[$VMNAME]\nlabel = $VMNAME\nplatform = windows\nip = 10.200.0.20" >> $CUCKOODIR/conf/virtualbox.conf
done
INSTALLEDVMS=$(su - cuckoo -c "vboxmanage list vms"|awk '{print $1}'|sed 's/"//g'|tr '\n' ','|sed 's/.$//g')
sed -i "s/machines = .*/machines = $INSTALLEDVMS/g" $CUCKOODIR/conf/virtualbox.conf

#Fail2Ban
echo "Setting Fail2Ban to drop"
sed -i 's/blocktype =.*/blocktype = DROP/g' /etc/fail2ban/action.d/iptables-common.conf

# It's certificate time
echo "Setting up certificates"
openssl genrsa -out ca.key 8192



# Generate CSR 
openssl req -new -key ca.key -out ca.csr

# Generate Self Signed Key
openssl x509 -req -days 365 -in ca.csr -signkey ca.key -out ca.crt

# Copy the files to the correct locations
cp ca.crt /etc/pki/tls/certs
cp ca.key /etc/pki/tls/private/$HOSTNAME.key
cp ca.csr /etc/pki/tls/private/$HOSTNAME.csr


# If you use our configuration you have to maintain your backend cuckooweb port here
# Default is 127.0.0.1:8000
echo "Setting up HTTPD"
/bin/cp -f httpd/cuckoo.conf /etc/httpd/conf.d/
sed -i "s/EMAIL REPLACE/${EMAIL}/g" /etc/httpd/conf.d/cuckoo.conf
sed -i "s/HOSTNAME REPLACE/${HOSTNAME}/g" /etc/httpd/conf.d/cuckoo.conf
#cp httpd/cuckoo.conf /etc/httpd/conf.d/

echo "Setting up Docker networks and containers if they don't already exist"
mkdir -p "${DOCKER_MONGO_DIR}"
#TODO: Start containers if they exist?
[ ! "$(docker network ls | grep mongo)" ] && docker network create --subnet=${DOCKER_MONGO_NET} mongo
[ ! "$(docker network ls | grep es)" ] && docker network create --subnet=${DOCKER_ELASTIC_NET} es
sudo [ ! "$(docker ps -a | grep cuckoo-mongo)" ] && docker run --restart always -d --name cuckoo-mongo --net mongo --ip ${DOCKER_MONGO_IP} -p 27017:27017 -v ${DOCKER_MONGO_DIR}:/data/db mongo
#TODO: Is this going to install ES6?  Doesn't Moloch not support ES6?
sudo [ ! "$(docker ps -a | grep cuckoo-elastic)" ] && docker run --restart always -d --name cuckoo-elastic --net es --ip ${DOCKER_ELASTIC_IP} -p 9200:9200 -p 9300:9300 -v ${DOCKER_ELASTIC_DIR}:/data/elastic -e "discovery.type=single-node" docker.elastic.co/elasticsearch/elasticsearch:5.6.6
# waiting for es to come up
sleep 5
echo "Adding elasticsearch hunt template"
#TODO: Verify that this is idempotent
curl -XPUT "${DOCKER_ELASTIC_IP}:9200/_template/hunt" -d "$(<elastic/elastic.template)"

echo "Adding init.d scripts to start cuckoo at system start"
cp init.d/* /etc/init.d/



# Download and install moloch
dpkg -i https://files.molo.ch/builds/ubuntu-16.04/moloch_0.50.0-1_amd64.deb

id -u ${CUCKOO_USER}
if [ $? -eq 1 ]; then
echo "Adding user "+${CUCKOO_USER}
adduser "${CUCKOO_USER}"
fi

chown -R "${CUCKOO_USER}.${CUCKOO_USER}" "${CUCKOODIR}"
replace_templates /etc/init.d/cuckoo*

echo "Editing Crontab"

/bin/cp -rf ${CUCKOODIR}/install/crontab/scripts ${CUCKOODIR}/utils/crontab

for file in  $(find ${CUCKOODIR}/utils/crontab/*); do
    replace_templates file
done
chown -R root.root ${CUCKOODIR}/utils/crontab/root

edit_crontab "$(<crontab/crontab_root.template)" "$(id -u)"
edit_crontab "$(<crontab/crontab.template)" "${CUCKOO_USER}"

echo "Done!"

# This takes us to POST image creation
# Import existing images and use them to continue

