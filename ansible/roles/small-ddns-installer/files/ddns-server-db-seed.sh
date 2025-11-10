#!/usr/bin/env bash

#DBFILE=~/bin/tralala.db
# DBFILE=/var/lib/ddns/hosts.db
DBFILE=/var/lib/ddns/db/hosts.db

### Remove the existing sqlite db.
#rm ${DBFILE}

### Create and seed the sqlite db.
mkdir -p $(dirname $DBFILE) &>/dev/null

# Create the database
cat <<EOSQL | sqlite3 ${DBFILE}
CREATE TABLE clients(
	token TEXT PRIMARY KEY NOT NULL,
	hostname TEXT NOT NULL,
	owner TEXT NOT NULL,
	ipaddress TEXT,
	ip6address TEXT,
	created_at TIMESTAMP NOT NULL,
	last_update TIMESTAMP NOT NULL
);
EOSQL

# Fix permissions
chmod 0777 $(dirname $DBFILE)
chmod 0666 $DBFILE

# Seed the database with 10 records
for i in {1..10}
do
	n=$(( i % 3))
cat <<EOSQL | sqlite3 ${DBFILE}
	INSERT INTO clients(
		hostname, owner, created_at, last_update, token )
		VALUES (
		"hostname${i}.example.com",
		"user${n}",
		datetime('$(date -d "now - ${i}hours" "+%F %H:%M:%S")'),
		datetime('now'),
		"$(tr -d '-' < /proc/sys/kernel/random/uuid)"
	)
EOSQL
done
