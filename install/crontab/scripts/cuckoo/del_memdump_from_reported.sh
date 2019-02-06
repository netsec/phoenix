#!/bin/bash
MARKER="/opt/phoenix/utils/mem_prep"
#STORAGE="/opt/phoenix/storage/analyses"
#STORAGE="/ssd/cuckoo_tmp/"
STORAGE="/dev/shm"
mysql -B -h 172.18.1.252 --user="CUCKOO_USER" --password="DOCKER_MYSQL_PASSWORD" --database="DOCKER_MYSQL_DATABASE" --execute="select id from tasks where status in ('reported', 'failed_processing', 'failed_analysis', 'failed_reporting') order by id desc limit 1000;" 2>/dev/null|grep -v 'id' |while read id; do
	CHECK=$(grep "^$id$" "$MARKER")
	if [ -z "$CHECK" ]; then
		echo "`date` deleting memory dump for $id"
		rm -f "$STORAGE/$id.dmp"
                echo "$id" >> "$MARKER"
		
	fi
done
find /tmp/tmp* -type f -mmin +5|while read file; do rm -f $file ;done