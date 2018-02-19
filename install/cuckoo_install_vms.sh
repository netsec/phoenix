#!/bin/bash
set -e
CUCKOOVBOX="$1"
SAND_INT="$2"
SAND_IP="$3"
ls vbox_templates/*.ova|while read newvm; do
    VMNAME=$(echo $newvm|sed 's/\.ova//g'|awk -F '/' '{print $NF}')
    vboxmanage import ${newvm}
    echo -e "[$VMNAME]\nlabel = $VMNAME\nplatform = windows\nip = 10.200.0.20" >> $CUCKOOVBOX
done
vboxmanage hostonlyif ipconfig "$SAND_INT" --ip "$SAND_IP" --netmask 255.255.255.0