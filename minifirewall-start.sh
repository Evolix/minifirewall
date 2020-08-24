#!/bin/sh

# minifirewall
# See https://gitea.evolix.org/evolix/minifirewall

# Copyright (c) 2007-2020 Evolix
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License.

# Description
# script for standalone server

# Start minifirewall
#

# Variables configuration
#########################

# nft path
NFT=/usr/sbin/nft

# Configuration
configfile="/etc/default/minifirewall"

DOCKER=$(grep "DOCKER=" /etc/default/minifirewall | awk -F '='  -F "'" '{print $2}')
INT=$(grep "INT=" /etc/default/minifirewall | awk -F '='  -F "'" '{print $2}')

# sysctl network security settings
##################################

# Don't answer to broadcast pings
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Ignore bogus ICMP responses
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Disable Source Routing
for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do
echo 0 > $i
done

# Enable TCP SYN cookies to avoid TCP-SYN-FLOOD attacks
# cf http://cr.yp.to/syncookies.html
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Disable ICMP redirects
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do
echo 0 > $i
done

for i in /proc/sys/net/ipv4/conf/*/send_redirects; do
echo 0 > $i
done

# Enable Reverse Path filtering : verify if responses use same network interface
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do
echo 1 > $i
done

# log des paquets avec adresse incoherente
for i in /proc/sys/net/ipv4/conf/*/log_martians; do
echo 1 > $i
done

# IPTables configuration
########################

if ! test -f $configfile; then
    echo "$configfile does not exist" >&2
    exit 1
fi

. $configfile

# Flush everything first
$NFT flush ruleset

# Add a filter table
$NFT add table inet minifirewall

# Add the input, forward, and output base chains. The policy for input and forward will be to drop. The policy for output will be to accept.
$NFT add chain inet minifirewall minifirewall_input '{ type filter hook input priority 0 ; policy drop ; }'
$NFT add chain inet minifirewall minifirewall_forward '{ type filter hook forward priority 0 ; policy drop ; }'
$NFT add chain inet minifirewall minifirewall_output '{ type filter hook output priority 0 ; policy accept ; }'

# Add set with trusted IP addresses
#$NFT define minifirewall_trusted_ips = {$(echo $TRUSTEDIPS | sed 's/ /, /g')}
$NFT add set inet minifirewall minifirewall_trusted_ips { type ipv4_addr\;}
$NFT add element inet minifirewall minifirewall_trusted_ips {$(echo $TRUSTEDIPS | sed 's/ /, /g')}

# Add set with  privileged IP addresses
#$NFT define minifirewall_privileged_ips = {$(echo $PRIVILEGIEDIPS | sed 's/ /, /g')}
$NFT add set inet minifirewall minifirewall_privileged_ips { type ipv4_addr\;}
$NFT add element inet minifirewall minifirewall_privileged_ips {$(echo $PRIVILEGIEDIPS | sed 's/ /, /g')}

# Add TCP/UDP chains for protected, public, semi-public and private ports
$NFT add chain inet minifirewall protected_tcp_ports
$NFT add chain inet minifirewall protected_udp_ports
$NFT add chain inet minifirewall public_tcp_ports
$NFT add chain inet minifirewall public_udp_ports
$NFT add chain inet minifirewall semipublic_tcp_ports
$NFT add chain inet minifirewall semipublic_udp_ports
$NFT add chain inet minifirewall private_tcp_ports
$NFT add chain inet minifirewall private_udp_ports

# Related and established traffic is accepted
$NFT add rule inet minifirewall minifirewall_input ct state related,established accept

# All loopback interface traffic is accepted
$NFT add rule inet minifirewall minifirewall_input iif lo accept

# Allow services for $INTLAN (local server or local network) is accepted
$NFT add rule inet minifirewall minifirewall_input ip saddr $INTLAN accept

# Any invalid traffic is dropped
$NFT add rule inet minifirewall minifirewall_input ct state invalid drop

# ICMP and IGMP traffic is accepted
$NFT add rule inet minifirewall minifirewall_input meta l4proto ipv6-icmp icmpv6 type '{ destination-unreachable, packet-too-big, time-exceeded, parameter-problem, mld-listener-query, mld-listener-report, mld-listener-reduction, nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, ind-neighbor-solicit, ind-neighbor-advert, mld2-listener-report }' accept
$NFT add rule inet minifirewall minifirewall_input meta l4proto icmp icmp type '{ destination-unreachable, router-solicitation, router-advertisement, time-exceeded, parameter-problem }' accept
$NFT add rule inet minifirewall minifirewall_input ip protocol igmp accept

# New UDP traffic from trusted IPs jumps to the private_udp_ports chain
$NFT add rule inet minifirewall minifirewall_input 'ip saddr @minifirewall_trusted_ips meta l4proto udp ct state new jump private_udp_ports'

# New TCP traffic from trusted IPs jumps to the private_tcp_ports chain
$NFT add rule inet minifirewall minifirewall_input 'ip saddr @minifirewall_trusted_ips meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new jump private_tcp_ports'

# New UDP traffic from trusted IPs and privileged IPs jumps to the semipublic_udp_ports chain
$NFT add rule inet minifirewall minifirewall_input 'ip saddr @minifirewall_privileged_ips meta l4proto udp ct state new jump semipublic_udp_ports'
$NFT add rule inet minifirewall minifirewall_input 'ip saddr @minifirewall_trusted_ips meta l4proto udp ct state new jump semipublic_udp_ports'

# New TCP traffic from trusted IPs and privileged IPs jumps to the semipublic_tcp_ports chain
$NFT add rule inet minifirewall minifirewall_input 'ip saddr @minifirewall_privileged_ips meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new jump semipublic_tcp_ports'
$NFT add rule inet minifirewall minifirewall_input 'ip saddr @minifirewall_trusted_ips meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new jump semipublic_tcp_ports'

# New UDP traffic from any other IP jumps to the public_udp_ports chain
$NFT add rule inet minifirewall minifirewall_input 'meta l4proto udp ct state new jump public_udp_ports'

# New TCP traffic from any other IP jumps to the public_tcp_ports chain
$NFT add rule inet minifirewall minifirewall_input 'meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new jump public_tcp_ports'

# Reject all traffic that was not processed by other rules
$NFT add rule inet minifirewall minifirewall_input meta l4proto udp reject
$NFT add rule inet minifirewall minifirewall_input meta l4proto tcp reject with tcp reset
$NFT add rule inet minifirewall minifirewall_input counter reject with icmpx type port-unreachable

# Feed public_tcp_ports chain with public TCP ports
for x in $SERVICESTCP1
    do
        $NFT add rule inet minifirewall public_tcp_ports tcp dport $x accept
    done

# Feed public_udp_ports chain with public UDP ports
for x in $SERVICESUDP1
    do
        $NFT add rule inet minifirewall public_tcp_ports udp dport $x accept
    done

# Feed semipublic_tcp_ports chain with semi-public TCP ports
for x in $SERVICESTCP2
    do
        $NFT add rule inet minifirewall semipublic_tcp_ports tcp dport $x accept
    done

# Feed semipublic_udp_ports chain with semi-public UDP ports
for x in $SERVICESUDP2
    do
        $NFT add rule inet minifirewall semipublic_udp_ports udp dport $x accept
    done

# Feed private_tcp_ports chain with private TCP ports
for x in $SERVICESTCP3
    do
        $NFT add rule inet minifirewall private_tcp_ports tcp dport $x accept
    done

# Feed private_udp_ports chain with private UDP ports
for x in $SERVICESUDP3
    do
        $NFT add rule inet minifirewall private_udp_ports udp dport $x accept
    done

# Feed protected_tcp_ports chain with protected TCP ports
for x in $SERVICESTCP1p
    do
        $NFT add rule inet minifirewall protected_tcp_ports tcp dport $x accept
    done

# Feed protected_udp_ports chain with protected UDP ports
for x in $SERVICESUDP1p
    do
        $NFT add rule inet minifirewall protected_udp_ports udp dport $x accept
    done





### We avoid "martians" packets, typical when W32/Blaster virus
## attacked windowsupdate.com and DNS was changed to 127.0.0.1
## $NFT -t NAT -I PREROUTING -s $LOOPBACK -i ! lo -j DROP
#$NFT -A INPUT -s $LOOPBACK ! -i lo -j DROP
#
#
#if [ "$DOCKER" = "on" ]; then
#
#    $NFT -N MINIFW-DOCKER-TRUSTED
#    $NFT -A MINIFW-DOCKER-TRUSTED -j DROP
#
#    $NFT -N MINIFW-DOCKER-PRIVILEGED
#    $NFT -A MINIFW-DOCKER-PRIVILEGED -j MINIFW-DOCKER-TRUSTED
#    $NFT -A MINIFW-DOCKER-PRIVILEGED -j RETURN
#
#    $NFT -N MINIFW-DOCKER-PUB
#    $NFT -A MINIFW-DOCKER-PUB -j MINIFW-DOCKER-PRIVILEGED
#    $NFT -A MINIFW-DOCKER-PUB -j RETURN
#
#    # Flush DOCKER-USER if exist, create it if absent
#    if chain_exists 'DOCKER-USER'; then
#        $NFT -F DOCKER-USER
#    else
#        $NFT -N DOCKER-USER
#    fi;
#
#    # Pipe new connection through MINIFW-DOCKER-PUB
#    $NFT -A DOCKER-USER -i $INT -m state  --state NEW -j MINIFW-DOCKER-PUB
#    $NFT -A DOCKER-USER -j RETURN
#
#fi
#
#
## Local services restrictions
##############################
#
#if [ "$DOCKER" = "on" ]; then
#
#    # Public services defined in SERVICESTCP1 & SERVICESUDP1
#    for dstport in $SERVICESTCP1
#        do
#            $NFT -I MINIFW-DOCKER-PUB -p tcp --dport "$dstport" -j RETURN
#        done
#
#    for dstport in $SERVICESUDP1
#        do
#            $NFT -I MINIFW-DOCKER-PUB -p udp --dport "$dstport" -j RETURN
#        done
#
#    # Privileged services (accessible from privileged & trusted IPs)
#    for dstport in $SERVICESTCP2
#        do
#            for srcip in $PRIVILEGIEDIPS
#                do
#                    $NFT -I MINIFW-DOCKER-PRIVILEGED -p tcp -s "$srcip" --dport "$dstport" -j RETURN
#                done
#
#            for srcip in $TRUSTEDIPS
#                do
#                    $NFT -I MINIFW-DOCKER-PRIVILEGED -p tcp -s "$srcip" --dport "$dstport" -j RETURN
#                done
#        done
#
#    for dstport in $SERVICESUDP2
#        do
#            for srcip in $PRIVILEGIEDIPS
#                do
#                    $NFT -I MINIFW-DOCKER-PRIVILEGED -p udp -s "$srcip" --dport "$dstport" -j RETURN
#                done
#
#            for srcip in $TRUSTEDIPS
#                do
#                    $NFT -I MINIFW-DOCKER-PRIVILEGED -p udp -s "$srcip" --dport "$dstport" -j RETURN
#                done
#        done
#
#    # Trusted services (accessible from trusted IPs)
#    for dstport in $SERVICESTCP3
#        do
#            for srcip in $TRUSTEDIPS
#                do
#                    $NFT -I MINIFW-DOCKER-TRUSTED -p tcp -s "$srcip" --dport "$dstport" -j RETURN
#                done
#        done
#
#    for dstport in $SERVICESUDP3
#        do
#            for srcip in $TRUSTEDIPS
#                do
#                    $NFT -I MINIFW-DOCKER-TRUSTED -p udp -s "$srcip" --dport "$dstport" -j RETURN
#                done
#        done
#fi
#
## External services
####################
#
## DNS authorizations
#for x in $DNSSERVEURS
#    do
#        $NFT -A INPUT -p tcp ! --syn --sport 53 --dport $PORTSUSER -s $x -j ACCEPT
#        $NFT -A INPUT -p udp --sport 53 --dport $PORTSUSER -s $x -m state --state ESTABLISHED,RELATED -j ACCEPT
#        $NFT -A OUTPUT -o $INT -p udp -d $x --dport 53 --match state --state NEW -j ACCEPT
#    done
#
## HTTP (TCP/80) authorizations
#for x in $HTTPSITES
#    do
#        $NFT -A INPUT -p tcp ! --syn --sport 80 --dport $PORTSUSER -s $x -j ACCEPT
#    done
#
## HTTPS (TCP/443) authorizations
#for x in $HTTPSSITES
#    do
#        $NFT -A INPUT -p tcp ! --syn --sport 443 --dport $PORTSUSER -s $x -j ACCEPT
#    done
#
## FTP (so complex protocol...) authorizations
#for x in $FTPSITES
#    do
#        # requests on Control connection
#        $NFT -A INPUT -p tcp ! --syn --sport 21 --dport $PORTSUSER -s $x -j ACCEPT
#        # FTP port-mode on Data Connection
#        $NFT -A INPUT -p tcp --sport 20 --dport $PORTSUSER -s $x -j ACCEPT
#        # FTP passive-mode on Data Connection
#        # WARNING, this allow all connections on TCP ports > 1024
#        $NFT -A INPUT -p tcp ! --syn --sport $PORTSUSER --dport $PORTSUSER -s $x -j ACCEPT
#    done
#
## SSH authorizations
#for x in $SSHOK
#        do
#                $NFT -A INPUT -p tcp ! --syn --sport 22 -s $x -j ACCEPT
#        done
#
## SMTP authorizations
#for x in $SMTPOK
#    do
#        $NFT -A INPUT -p tcp ! --syn --sport 25 --dport $PORTSUSER -s $x -j ACCEPT
#    done
#
## secure SMTP (TCP/465 et TCP/587) authorizations
#for x in $SMTPSECUREOK
#    do
#        $NFT -A INPUT -p tcp ! --syn --sport 465 --dport $PORTSUSER -s $x -j ACCEPT
#        $NFT -A INPUT -p tcp ! --syn --sport 587 --dport $PORTSUSER -s $x -j ACCEPT
#    done
#
## NTP authorizations
#for x in $NTPOK
#        do
#            $NFT -A INPUT -p udp --sport 123 -s $x -j ACCEPT
#            $NFT -A OUTPUT -o $INT -p udp -d $x --dport 123 --match state --state NEW -j ACCEPT
#        done
#
## Always allow ICMP
#$NFT -A INPUT -p icmp -j ACCEPT
#[ "$IPV6" != "off" ] && $NFT6 -A INPUT -p icmpv6 -j ACCEPT

trap - INT TERM EXIT

echo "...starting NFTables rules is now finish : OK"

exit 0
