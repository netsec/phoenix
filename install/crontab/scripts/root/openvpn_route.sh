#!/bin/bash
for i in {0..35}; do
	ip route list dev tun$i|while read rule; do
		ip route add $rule dev tun$i table tun$i
	done
	GW=`ip route show dev tun$i|grep kernel|awk '{print $1}'`
	ip route add 0.0.0.0/1 via $GW dev tun$i table tun$i
	ip route add 128.0.0.0/1 via $GW dev tun$i table tun$i
done
