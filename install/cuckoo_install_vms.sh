#!/bin/bash
SAND_INT="$1"
SAND_IP="$2"
VBOXDIR=$(vboxmanage list systemproperties|grep "Default machine folder:"|awk -F 'Default machine folder:' '{print $2}'|sed -e 's/^          //g')
echo "VBox machine folder is $VBOXDIR"

VBOXCHECK=$(vboxmanage list vms)
if [ -n "$VBOXCHECK" ]; then
    echo "Cowardly refusing to install VMs, since you already have VMs setup"
    exit 0
fi
OVAS=$(ls vbox_templates/*.ova 2>/dev/null)
if [ -n "$OVAS" ]; then
    echo "Found OVA file(s)... installing them"
    ls vbox_templates/*.ova|while read newvm; do
        VMNAME=$(echo $newvm|sed 's/\.ova//g'|awk -F '/' '{print $NF}')
        vboxmanage import ${newvm}
    done
fi

echo "###################### THIS IS IMPORTANT ###############################"
echo "########################################################################"
echo "#"
echo "#                                             ...."
echo "#.                                        ,,,,."
echo "#.                                   .,,,,,"
echo "#..                              .,,,,,."
echo "# ..                         ,,,,,,,."
echo "# ...                   .,,,,,,,."
echo "#  ...              ,,,,,,,,,."
echo "#  ....        .,,,,,,,,,,       There is no **clean** way to know what "
echo "#   ....      .,,,,,,,.          VM IP addresses you have just imported"
echo "#   .....     ,,,,,              In order to make cuckoo work, please "
echo "#    .....    ,,,,,              setup your machinery in "
echo "#              ,,,,              /opt/phoenix/conf/virtualbox.conf"
echo "#   ,,,,        ,,,.             or wherever you've setup phoenix"
echo "# ,,,,,    ..   .,,."
echo "#,,       ....   .,."
echo "#        .....    .,"
echo "#       .....      ."
echo "#      ...."
echo "#     ...."
echo "#    ..."
echo "#  ...."
echo "# ..."
echo "#"
echo "########################################################################"

vboxmanage hostonlyif ipconfig "$SAND_INT" --ip "$SAND_IP" --netmask 255.255.255.0