#!/bin/bash
if [ ! -f /var/run/cuckoo_monitor ]; then
/etc/init.d/cuckoo_all status|grep NOT|awk '{print $1}' |while read line; do
	echo "Restarting $line - `date`" >> /var/log/cuckoo/debug/monitor.`date +%Y%m%d`.log
	echo "Restarted $line - `date`" | mail -s "Phoenix.beastmode.tools $line restart" jborland@sparkits.ca
	/etc/init.d/$line restart
done
fi
