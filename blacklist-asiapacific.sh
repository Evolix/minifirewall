#!/bin/sh

# use it with /sbin/iptables -I INPUT -m set --match-set apnic-ipv4 src -j DROP

cd /var/tmp

rm -f $apnicdeny_file

GET http://antispam00.evolix.org/spam/apnic.cidr.md5 > apnic.cidr.md5
GET http://antispam00.evolix.org/spam/apnic.cidr > apnic.cidr

ipset destroy apnic-ipv4
ipset create apnic-ipv4 hash:net

for i in $(cat /var/tmp/apnic.cidr); do
    BLOCK=$(echo $i | cut -d"|" -f2)
    /sbin/ipset add apnic-ipv4 $BLOCK
done
