#!/usr/bin/env bash
set -euf -o pipefail

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <demo|production> <smtp-relay>"
    exit 1
fi

ENV="$1"
SMTP_RELAY="$2"

case "$ENV" in
    demo|production)
        ;;
    *)
        echo "Usage: $0 <demo|production> <smtp-relay>"
        exit 1
        ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
ENV_FILE="${REPO_DIR}/backend/envs/${ENV}/.env"

if [[ ! -f "$ENV_FILE" ]]; then
    echo "Environment file not found: $ENV_FILE" >&2
    exit 1
fi

set_env_value() {
    local key="$1"
    local value="$2"
    local temp_file
    temp_file="$(mktemp)"

    awk -v key="$key" -v value="$value" '
        BEGIN { done = 0 }
        $0 ~ "^[[:space:]]*#?[[:space:]]*" key "=" {
            if (!done) {
                print key "=" value
                done = 1
            }
            next
        }
        { print }
        END {
            if (!done) {
                print key "=" value
            }
        }
    ' "$ENV_FILE" > "$temp_file"

    mv "$temp_file" "$ENV_FILE"
}

set_env_value "BACKEND_SMTP_HOST" "$SMTP_RELAY"
set_env_value "BACKEND_SMTP_PORT" "587"
set_env_value "BACKEND_SMTP_SENDER_EMAIL" "bestuur@dsavdodeka.nl"
set_env_value "BACKEND_SMTP_SENDER_NAME" "D.S.A.V. Dodeka"
set_env_value "BACKEND_SMTP_SEND" "true"

echo "Enabled SMTP for ${ENV}:"
echo "  ${ENV_FILE}"
echo "  relay=${SMTP_RELAY}"
echo ""
echo "Restart the ${ENV} backend for this to take effect:"
echo "  ~/dodeka/deploy/restart-${ENV}.sh"
