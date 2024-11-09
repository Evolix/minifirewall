#!/bin/sh

cd /var/tmp

rm -f $apnicdeny_file

GET http://antispam00.evolix.org/spam/apnic.cidr.md5 > apnic.cidr.md5
GET http://antispam00.evolix.org/spam/apnic.cidr > apnic.cidr

/sbin/iptables -F NEEDRESTRICT

for i in $(cat /var/tmp/apnic.cidr); do
    BLOCK=$(echo $i | cut -d"|" -f2)
    /sbin/iptables -I NEEDRESTRICT -s $BLOCK -j DROP
done
