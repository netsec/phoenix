#!/bin/bash
VPNS=REPLACEVPNS
for i in $VPNS; do
	ip route list dev $i|while read rule; do
		ip route add $rule dev $i table $i
	done
	GW=`ip route show dev $i|grep kernel|awk '{print $1}'`
	ip route add 0.0.0.0/1 via $GW dev $i table $i
	ip route add 128.0.0.0/1 via $GW dev $i table $i
done
