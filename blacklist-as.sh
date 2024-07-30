#!/bin/sh

# Only IPv4 (could be easily IPv6 but need minfirewall / NEEDRESTRICT IPv6-compatible first)

rpkideny_file=/var/tmp/rpki_deny

cd /var/tmp

rm -f $rpkideny_file

GET http://antispam00.evolix.org/spam/rpki.cidr.md5 > rpki.cidr.md5
GET http://antispam00.evolix.org/spam/rpki.cidr > rpki.cidr

for i in 4134; do

    grep "^$i," rpki.cidr | grep -v '::' >> $rpkideny_file

done

/sbin/iptables -F NEEDRESTRICT

for i in $(cat $rpkideny_file); do
    BLOCK=$(echo $i | cut -d, -f2)
    /sbin/iptables -I NEEDRESTRICT -s $BLOCK -j DROP
done
