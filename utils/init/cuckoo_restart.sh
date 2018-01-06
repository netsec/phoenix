#!/bin/bash
pkill cuckoo_monitor.sh
touch /var/run/cuckoo_monitor
for i in cuckoo_all openvpn; do
	/etc/init.d/$i stop
done
pkill ping
/etc/init.d/iptables restart
/etc/init.d/fail2ban restart
/etc/init.d/docker restart
/etc/init.d/openvpn start
sleep 10
/root/.scripts/fix_openvpn.sh >/dev/null 2>&1
/root/.scripts/nw.sh
/etc/init.d/cuckoo_all start
/root/.scripts/fix_openvpn.sh >/dev/null 2>&1
/root/.scripts/nw.sh
rm -f /var/run/cuckoo_monitor
sleep 10
/root/.scripts/fix_openvpn.sh >/dev/null 2>&1
