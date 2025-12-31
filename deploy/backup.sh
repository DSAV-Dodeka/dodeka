#!/bin/bash

DB_PATH="/home/backend/dodeka/backend/db.sqlite"
BACKUP_DIR="/mnt/backup/demo-backups"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LATEST="${BACKUP_DIR}/db_latest.sqlite"

# Ensure backup directory exists
mkdir -p "$BACKUP_DIR"

# Snapshot the current "latest" before modifying it
if [[ -f "$LATEST" ]]; then
    cp --reflink=always "$LATEST" "${BACKUP_DIR}/db_${TIMESTAMP}.sqlite"
    echo "Created snapshot: db_${TIMESTAMP}.sqlite"
fi

# Update "latest" with fresh backup
sqlite3 "$DB_PATH" ".backup '$LATEST'"
echo "Updated latest backup"

# Optional: remove backups older than 30 days
find "$BACKUP_DIR" -name "db_*.sqlite" -mtime +30 -delete
