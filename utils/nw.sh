#!/bin/bash
for i in {0..35}; do 
	ifconfig tun$i|grep 'inet addr'|awk -F 'addr:' '{print $2}'|awk '{print $1}'|sed -r 's/[0-9]+$/1/g'|while read ip ; do 
		ping -I tun$i -nn -W 5 -i 120 -s 20 -p 4b6565702d416c697665 $ip >> /var/log/ping.log 2>&1 &
		#C=`ping -c3 $ip |grep "100% packet loss"`
		#if [ -n "$C" ]; then
		#	S=0
		#else
		#	S=1
		#fi
		#echo "{ \"ts\" : \"`date`\", \"int\" : \"tun${i}\", \"ip\" : \"$ip\", \"status\" : $S }"
	done
done
