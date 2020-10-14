#!/bin/sh

NFT=/usr/sbin/nft
ripedeny_file=/var/tmp/ripe_deny

cd /var/tmp

rm -f $ripedeny_file

GET http://antispam00.evolix.org/spam/ripe.cidr.md5 > ripe.cidr.md5
GET http://antispam00.evolix.org/spam/ripe.cidr > ripe.cidr

for i in CN KR RU; do
    grep "^$i|" ripe.cidr >> $ripedeny_file
done

for i in $(cat $ripedeny_file); do
    BLOCK=$(echo $i | cut -d"|" -f2)
    $NFT add element inet minifirewall minifirewall_blocked_ips {$BLOCK}
done
