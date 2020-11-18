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

#########################
## NFTables configuration
#########################

if ! test -f $configfile; then
    echo "$configfile does not exist" >&2
    exit 1
fi

# Parse configuration file
. $configfile

# Flush everything first
$NFT flush ruleset

# Add a filter table
$NFT add table inet minifirewall

# Add the input, forward, and output base chains. The default policy will be to drop the traffic.
$NFT add chain inet minifirewall minifirewall_input '{ type filter hook input priority 0 ; policy drop ; }'
$NFT add chain inet minifirewall minifirewall_forward '{ type filter hook forward priority 0 ; policy drop ; }'
$NFT add chain inet minifirewall minifirewall_output '{ type filter hook output priority 0 ; policy drop ; }'

# Add set with trusted IP addresses
$NFT add set inet minifirewall minifirewall_trusted_ips '{ type ipv4_addr ; flags interval ;}'
$NFT add element inet minifirewall minifirewall_trusted_ips {$(echo $TRUSTEDIPS | sed 's/ /, /g')}

# Add set with privileged IP addresses
$NFT add set inet minifirewall minifirewall_privileged_ips '{ type ipv4_addr ; flags interval ;}'
$NFT add element inet minifirewall minifirewall_privileged_ips {$(echo $PRIVILEGIEDIPS | sed 's/ /, /g')}

# Add set for blocked IP addresses
$NFT add set inet minifirewall minifirewall_blocked_ips '{ type ipv4_addr ; flags interval ;}'
# Add TCP/UDP chains for protected, public, semi-public and private ports
$NFT add chain inet minifirewall protected_tcp_ports
$NFT add chain inet minifirewall protected_udp_ports
$NFT add chain inet minifirewall public_tcp_ports
$NFT add chain inet minifirewall public_udp_ports
$NFT add chain inet minifirewall semipublic_tcp_ports
$NFT add chain inet minifirewall semipublic_udp_ports
$NFT add chain inet minifirewall private_tcp_ports
$NFT add chain inet minifirewall private_udp_ports

################
## Input traffic
################
# Related and established traffic is accepted
$NFT add rule inet minifirewall minifirewall_input ct state related,established accept

# All loopback interface traffic is accepted
$NFT add rule inet minifirewall minifirewall_input iif lo accept

# Allow services for $INTLAN (local server or local network) is accepted
$NFT add rule inet minifirewall minifirewall_input ip saddr $INTLAN accept

# Any invalid traffic is dropped
$NFT add rule inet minifirewall minifirewall_input ct state invalid drop

# ICMP and IGMP traffic is accepted
$NFT add rule inet minifirewall minifirewall_input ip protocol icmp accept
$NFT add rule inet minifirewall minifirewall_input ip protocol igmp accept

# New UDP traffic from blocked IPs jumps to the private_udp_ports chain
$NFT add rule inet minifirewall minifirewall_input 'ip saddr @minifirewall_blocked_ips meta l4proto udp ct state new jump protected_udp_ports'

# New TCP traffic from blocked IPs jumps to the private_tcp_ports chain
$NFT add rule inet minifirewall minifirewall_input 'ip saddr @minifirewall_blocked_ips meta l4proto tcp tcp flags & (fin|syn|rst|ack) == syn ct state new jump protected_tcp_ports'
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
        $NFT add rule inet minifirewall protected_tcp_ports tcp dport $x drop
    done

# Feed protected_udp_ports chain with protected UDP ports
for x in $SERVICESUDP1p
    do
        $NFT add rule inet minifirewall protected_udp_ports udp dport $x drop
    done

#####################################
## Output traffic / external services
#####################################

# Add set with $DNSSERVERS elements
$NFT add set inet minifirewall minifirewall_dnsservers { type ipv4_addr\;}
if [ ! -z $DNSSERVEURS ]
then
    if echo $DNSSERVEURS | grep -q "0.0.0.0/0"
    then
       # If 0.0.0.0/0 is present we allow any output on TCP/UDP port 53
       $NFT add rule inet minifirewall minifirewall_output udp dport 53 counter accept
       $NFT add rule inet minifirewall minifirewall_output tcp dport 53 counter accept
    else
       # Else we add each element to the minifirewall_dnsservers set and allow this set to be reached on TCP/UDP port 53
       $NFT add element inet minifirewall minifirewall_dnsservers {$(echo $DNSSERVEURS | sed 's/ /, /g')}
       $NFT add rule inet minifirewall minifirewall_output ip daddr @minifirewall_dnsservers udp dport 53 counter accept
       $NFT add rule inet minifirewall minifirewall_output ip daddr @minifirewall_dnsservers tcp dport 53 counter accept
    fi
fi

# Add set with $HTTPSITES elements
$NFT add set inet minifirewall minifirewall_httpsites { type ipv4_addr\;}
if [ ! -z $HTTPSITES ]
then
    if echo $HTTPSITES | grep -q "0.0.0.0/0"
    then
        # If 0.0.0.0/0 is present we allow any output on TCP port 80
        $NFT add rule inet minifirewall minifirewall_output tcp dport 80 counter accept
    else
        # Else we add each element to the minifirewall_httpsites set and allow this set to be reach on TCP port 80
        $NFT add element inet minifirewall minifirewall_httpsites {$(echo $HTTPSITES | sed 's/ /, /g')}
        $NFT add rule inet minifirewall minifirewall_output ip daddr @minifirewall_httpsites tcp dport 80 counter accept
    fi
fi

# Add set with $HTTPSSITES elements
$NFT add set inet minifirewall minifirewall_httpssites { type ipv4_addr\;}
if [ ! -z $HTTPSSITES ]
then
    if echo $HTTPSSITES | grep -q "0.0.0.0/0"
    then
        # If 0.0.0.0/0 is present we allow any output on TCP port 443
        $NFT add rule inet minifirewall minifirewall_output tcp dport 443 counter accept
    else
        # Else we add each element to the minifirewall_httpssites set and allow this set to be reach on TCP port 443
        $NFT add element inet minifirewall minifirewall_httpssites {$(echo $HTTPSSITES | sed 's/ /, /g')}
        $NFT add rule inet minifirewall minifirewall_output ip daddr @minifirewall_httpssites tcp dport 443 counter accept
    fi
fi

# Add set with $FTPSITES elements
$NFT add set inet minifirewall minifirewall_ftpsites { type ipv4_addr\;}
if [ ! -z $FTPSITES ]
then
    if echo $FTPSITES | grep -q "0.0.0.0/0"
    then
        # If 0.0.0.0/0 is present we allow any output on TCP ports 20, 21, 1024-65535
        $NFT add rule inet minifirewall minifirewall_output tcp dport {20, 21, 1024-65535} counter accept
    else
        # Else we add each element to the minifirewall_ftpsites set and allow this set to be reach on TCP ports 20, 21, 1024-65535
        $NFT add element inet minifirewall minifirewall_ftpsites {$(echo $FTPSITES | sed 's/ /, /g')}
        $NFT add rule inet minifirewall minifirewall_output ip daddr @minifirewall_ftpsites tcp dport {20, 21, 1024-65535} counter accept
    fi
fi

# Add set with $SSHOK elements
$NFT add set inet minifirewall minifirewall_sshok { type ipv4_addr\;}
if [ ! -z $SSHOK ]
then
    if echo $SSHOK | grep -q "0.0.0.0/0"
    then
        # If 0.0.0.0/0 is present we allow any output on TCP port 22
        $NFT add rule inet minifirewall minifirewall_output tcp dport 22 counter accept
    else
        # Else we add each element to the minifirewall_sshok set and allow this set to be reach on TCP port 22
        $NFT add element inet minifirewall minifirewall_sshok {$(echo $SSHOK | sed 's/ /, /g')}
        $NFT add rule inet minifirewall minifirewall_output ip daddr @minifirewall_sshok tcp dport 22 counter accept
    fi
fi

# Add set with $SMTPOK elements
$NFT add set inet minifirewall minifirewall_smtpok { type ipv4_addr\;}
if [ ! -z $SMTPOK ]
then
    if echo $SMTPOK | grep -q "0.0.0.0/0"
    then
        # If 0.0.0.0/0 is present we allow any output on TCP port 25
        $NFT add rule inet minifirewall minifirewall_output tcp dport 25 counter accept
    else
        # Else we add each element to the minifirewall_smtpok set and allow this set to be reach on TCP port 25
        $NFT add element inet minifirewall minifirewall_smtpok {$(echo $SMTPOK | sed 's/ /, /g')}
        $NFT add rule inet minifirewall minifirewall_output ip daddr @minifirewall_smtpok tcp dport 25 counter accept
    fi
fi

# Add set with $SMTPSECUREOK elements
$NFT add set inet minifirewall minifirewall_smtpsecureok { type ipv4_addr\;}
if [ ! -z $SMTPSECUREOK ]
then
    if echo $SMTPSECUREOK | grep -q "0.0.0.0/0"
    then
        # If 0.0.0.0/0 is present we allow any output on TCP ports 465 and 587
        $NFT add rule inet minifirewall minifirewall_output tcp dport {465, 587} counter accept
    else
        # Else we add each element to the minifirewall_smtpsecureok set and allow this set to be reach on TCP ports 465 and 587
        $NFT add element inet minifirewall minifirewall_smtpsecureok {$(echo $SMTPSECUREOK | sed 's/ /, /g')}
        $NFT add rule inet minifirewall minifirewall_output ip daddr @minifirewall_smtpsecureok tcp dport {465, 587} counter accept
    fi
fi

# Add set with $NTPOK elements
$NFT add set inet minifirewall minifirewall_ntpok { type ipv4_addr\;}
if [ ! -z $NTPOK ]
then
    if echo $NTPOK | grep -q "0.0.0.0/0"
    then
        # If 0.0.0.0/0 is present we allow any output on TCP ports 123
        $NFT add rule inet minifirewall minifirewall_output tcp dport 123 counter accept
    else
        # Else we add each element to the minifirewall_smtpsecureok set and allow this set to be reach on TCP port 123
        $NFT add element inet minifirewall minifirewall_ntpok {$(echo $NTPOK | sed 's/ /, /g')}
        $NFT add rule inet minifirewall minifirewall_output ip daddr @minifirewall_ntpok tcp dport 123 counter accept
    fi
fi

$NFT add rule inet minifirewall minifirewall_output ct state established,related accept

trap - INT TERM EXIT

echo "...starting NFTables rules is now finish : OK"

exit 0

