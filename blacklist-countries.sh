#!/bin/sh

# Only IPv4 (could be easily IPv6 too)

# use it with /sbin/iptables -I INPUT -m set --match-set countries-blocklist-v4 src -j DROP

ripedeny_file=/var/tmp/ripe_deny

cd /var/tmp

rm -f $ripedeny_file

GET http://antispam00.evolix.org/spam/ripe.cidr.md5 > ripe.cidr.md5
GET http://antispam00.evolix.org/spam/ripe.cidr > ripe.cidr

md5sum --status -c ripe.cidr.md5 || exit

for i in CN KR RU; do
    grep "^$i|" ripe.cidr >> $ripedeny_file
done

/sbin/iptables -D NEEDRESTRICT -m set --match-set countries-blocklist-v4 src -j DROP >/dev/null 2>&1
/sbin/ipset destroy countries-blocklist-v4 >/dev/null 2>&1

/sbin/ipset create countries-blocklist-v4 hash:net

for i in $(cat $ripedeny_file); do
    BLOCK=$(echo $i | cut -d"|" -f2)
    /sbin/ipset add countries-blocklist-v4 $BLOCK
done

/sbin/iptables -I NEEDRESTRICT -m set --match-set countries-blocklist-v4 src -j DROP
#/sbin/iptables -I INPUT -m set --match-set countries-blocklist-v4 src -j DROP

