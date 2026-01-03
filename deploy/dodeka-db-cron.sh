#!/usr/bin/env bash
set -euf -o pipefail

source "$(dirname "$0")/dodeka-db-common.sh"

# Default to production for scheduled backups
ENV="${1:-production}"
validate_env "$ENV" || exit 1

DB_PATH=$(get_db_path "$ENV")

printf "[%s] Starting scheduled backup for %s (%s)…\n" "$(date -Iseconds)" "$ENV" "$DB_PATH"

backup_db "$ENV"

printf "[%s] Backup complete. Pruning old snapshots…\n" "$(date -Iseconds)"

restic_cmd forget \
    --group-by host,tags \
    --tag "db_dodeka,env_${ENV}" \
    --keep-last 10 \
    --keep-hourly 24 \
    --keep-daily 7 \
    --keep-weekly 4 \
    --keep-monthly 6 \
    --prune

printf "[%s] Done.\n" "$(date -Iseconds)"
