#!/usr/bin/env bash
set -euf -o pipefail

source "$(dirname "$0")/dodeka-db-common.sh"

usage() {
    printf "Usage: %s <demo|production>\n" "$(basename "$0")"
    printf "\nBackup the database for the specified environment.\n"
    exit 1
}

[[ $# -lt 1 ]] && usage

ENV="$1"
validate_env "$ENV" || exit 1

DB_PATH=$(get_db_path "$ENV")

printf "Starting SQLite backup for %s (%s)…\n" "$ENV" "$DB_PATH"
backup_db "$ENV"
printf "Finished SQLite backup.\n"
