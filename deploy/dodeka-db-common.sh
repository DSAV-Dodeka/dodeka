#!/usr/bin/env bash
# Common configuration and functions for Dodeka database backup/restore

BACKEND_BASE="/home/backend/dodeka/backend"
RESTIC_REPO="/mnt/backup/restic"
RESTIC_PW_FILE="/mnt/backup/.restic-password"

# Get database path for environment
get_db_path() {
    local env="$1"
    echo "${BACKEND_BASE}/envs/${env}/db.sqlite"
}

# Get service name for environment
get_service_name() {
    local env="$1"
    echo "dodeka-backend-${env}"
}

# Validate environment argument
validate_env() {
    local env="$1"
    if [[ "$env" != "demo" && "$env" != "production" ]]; then
        printf "Error: Invalid environment '%s'. Must be 'demo' or 'production'.\n" "$env" >&2
        return 1
    fi
}

restic_cmd() {
    restic -r "$RESTIC_REPO" --password-file "$RESTIC_PW_FILE" "$@"
}

backup_db() {
    local env="$1"
    local extra_tags="${2:-}"
    local db_path=$(get_db_path "$env")
    local tags="db,db_sqlite,db_dodeka,env_${env}"
    [[ -n "$extra_tags" ]] && tags="${tags},${extra_tags}"

    local temp_dir=$(mktemp -d)
    trap 'rm -rf "$temp_dir"' RETURN

    sqlite3 "$db_path" "VACUUM INTO '${temp_dir}/dodeka-${env}.sqlite'"
    zstd --rsyncable -q "${temp_dir}/dodeka-${env}.sqlite" -o "${temp_dir}/dodeka-${env}.sqlite.zst"
    rm "${temp_dir}/dodeka-${env}.sqlite"

    restic_cmd backup \
        --retry-lock 1h \
        --group-by host,tags \
        --tag "$tags" \
        "${temp_dir}/dodeka-${env}.sqlite.zst"
}
