#!/bin/bash
psql -c 'SELECT version()' -U barman -h {{ db.container_name }} -p 3141 postgres || exit
service cron start
# It creates a slot, this might already exist but that isn't a problem
barman receive-wal --create-slot {{ db.barman_server_name }}
barman cron
# This requires barman to be a superuser
barman switch-wal {{ db.barman_server_name }}
barman cron
barman switch-wal --force --archive {{ db.barman_server_name }}
mkdir /var/lib/barman/log
# Create empty crontab
crontab -l 2>/dev/null
# 2 (stderr) to 1 (stdout), which is output to file
croncmd="barman cron >> /var/lib/barman/log/barman_cron.log 2>&1"
cronjob="* * * * * $croncmd"
# Add to cron without duplicating it
( crontab -l | grep -v -F "$croncmd" ; echo "$cronjob" ) | crontab -

croncmd="barman backup {{ db.barman_server_name }} >> /var/lib/barman/log/barman_backup.log 2>&1"
cronjob="0 4 * * * $croncmd"
( crontab -l | grep -v -F "$croncmd" ; echo "$cronjob" ) | crontab -

barman backup --wait {{ db.barman_server_name }}
barman check {{ db.barman_server_name }}

while true; do sleep 2; done