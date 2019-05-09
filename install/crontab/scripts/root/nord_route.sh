#!/bin/bash
#/etc/init.d/openvpn start
#VPNS="tun1 tun2 tun3 tun4 tun5 tun6 tun7 tun8 tun9 tun10"
VPNS="tun10"
for i in $VPNS; do
	GW=$(ip route list dev $i|awk '{print $NF}')
	#ip route list dev $i|while read rule; do
	#	ip route add $rule dev $i table $i
	#done
	#GW=`ip route show dev $i|grep kernel|awk '{print $1}'`
	ip route add 0.0.0.0/1 via $GW dev $i table $i
	ip route add 128.0.0.0/1 via $GW dev $i table $i
done
