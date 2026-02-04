#!/usr/bin/env bash
set -euf -o pipefail

source "$(dirname "$0")/dodeka-db-common.sh"

usage() {
    printf "Usage: %s <demo|production> [--from <demo|production>]\n" "$(basename "$0")"
    printf "\nRestore the database for the specified environment.\n"
    printf "\nOptions:\n"
    printf "  --from <env>  Restore from a different environment's backups\n"
    printf "                (e.g., restore production backup to demo)\n"
    printf "\nExamples:\n"
    printf "  %s demo                    # Restore demo from demo backups\n" "$(basename "$0")"
    printf "  %s demo --from production  # Restore demo from production backups\n" "$(basename "$0")"
    exit 1
}

[[ $# -lt 1 ]] && usage

TARGET_ENV="$1"
validate_env "$TARGET_ENV" || exit 1
shift

SOURCE_ENV="$TARGET_ENV"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --from)
            [[ $# -lt 2 ]] && { printf "Error: --from requires an environment argument.\n" >&2; exit 1; }
            SOURCE_ENV="$2"
            validate_env "$SOURCE_ENV" || exit 1
            shift 2
            ;;
        *)
            printf "Error: Unknown option '%s'\n" "$1" >&2
            usage
            ;;
    esac
done

TARGET_DB_PATH=$(get_db_path "$TARGET_ENV")
TARGET_SERVICE=$(get_service_name "$TARGET_ENV")

# List available snapshots for source environment
printf "Available snapshots for %s:\n\n" "$SOURCE_ENV"
restic_cmd snapshots --tag "db_dodeka,env_${SOURCE_ENV}"
printf "\n"

read -rp "Enter snapshot ID to restore (or 'latest'): " SNAPSHOT_ID
[[ -z "$SNAPSHOT_ID" ]] && { printf "No snapshot ID provided. Aborting.\n"; exit 1; }

if [[ "$SOURCE_ENV" != "$TARGET_ENV" ]]; then
    printf "\n⚠️  Cross-environment restore: %s → %s\n" "$SOURCE_ENV" "$TARGET_ENV"
fi
printf "\nThis will restore %s from snapshot %s.\n" "$TARGET_DB_PATH" "$SNAPSHOT_ID"
read -rp "Are you sure? Type 'yes' to continue: " CONFIRM
[[ "$CONFIRM" != "yes" ]] && { printf "Aborting.\n"; exit 1; }

# Stop service
printf "Stopping %s…\n" "$TARGET_SERVICE"
sudo systemctl stop "$TARGET_SERVICE"
sleep 1

# Backup current state before restoring
if [[ -f "$TARGET_DB_PATH" ]]; then
    printf "Backing up current %s database state…\n" "$TARGET_ENV"
    backup_db "$TARGET_ENV" "pre-restore"
fi

# Restore
printf "Restoring snapshot %s…\n" "$SNAPSHOT_ID"
RESTORE_DIR=$(mktemp -d)
trap 'rm -rf "$RESTORE_DIR"' EXIT

restic_cmd restore "$SNAPSHOT_ID" --target "$RESTORE_DIR"

RESTORED_FILE=$(find "$RESTORE_DIR" -name "*.sqlite.zst" -type f | head -1)
if [[ -z "$RESTORED_FILE" ]]; then
    printf "ERROR: No .sqlite.zst found in snapshot.\n"
    sudo systemctl start "$TARGET_SERVICE"
    exit 1
fi

zstd -d -q "$RESTORED_FILE" -o "${RESTORE_DIR}/restored.sqlite"

rm -f "${TARGET_DB_PATH}-wal" "${TARGET_DB_PATH}-shm"
mv "${RESTORE_DIR}/restored.sqlite" "$TARGET_DB_PATH"

printf "Starting %s…\n" "$TARGET_SERVICE"
sudo systemctl start "$TARGET_SERVICE"

printf "Done.\n"
