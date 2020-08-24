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

# Stop minifirewall
#

# Variables configuration
#########################

# nft path
NFT=/usr/sbin/nft

echo "Flush all rules and accept everything..."

# Flush everything
$NFT flush ruleset

echo "...flushing IPTables rules is now finish : OK"

exit 0
