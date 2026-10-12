#!/bin/sh
# Daily pg_dump of the SOC database into ./backups, pruning old files.
set -eu
while true; do
  ts=$(date -u +%Y%m%dT%H%M%SZ)
  if pg_dump -h db -U soc_owner -d soc -Fc -f "/backups/soc-$ts.dump"; then
    echo "backup ok: soc-$ts.dump"
    find /backups -name 'soc-*.dump' -mtime +"${BACKUP_KEEP_DAYS:-14}" -delete
  else
    echo "backup FAILED at $ts" >&2
  fi
  sleep 86400
done
