#!/usr/bin/env bash

### Read host records from the daabase, write to the hosts file.

# SQLFILE="/var/lib/ddns/hosts.db"
SQLFILE="/var/lib/ddns/db/hosts.db"
HOSTSFILE="/etc/dnsmasq.d/hosts.d/sysmgmt"

SELECT=".mode tabs
SELECT ipaddress, hostname from clients where ipaddress is not null;
SELECT ip6address, hostname from clients where ip6address is not null;"

echo "$SELECT" | sqlite3 $SQLFILE > $HOSTSFILE
