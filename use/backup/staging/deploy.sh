#!/bin/bash
# First argument is path for .env file to load (absolute or relative to this script!)
# If second argument is 'rv', it will remove the volume (so it starts from a clean slate)

# $0 is argument 0, which is always the script path
# % is a type of Parameter Expansion
# '/*' matches the last '/' and so %/* will remove everything after it
# This changes the directory to the directory containing the script
cd "${0%/*}" || exit
# This ensures all env variables are exported so env variables used in deploy.env (like $HOME) are
# properly expanded
# env files are consumed by e.g. docker compose
set -a
# Load environment variables from deploy.env file
. ./deploy.env
# -n means string is not null
if [ -n "$OVERRIDE_BARMAN_PASSWORD" ]; then
  BARMAN_PASSWORD="$OVERRIDE_BARMAN_PASSWORD"
fi

if [ "$1" = "rv" ]; then
   docker volume rm 'b-dodeka-backup-volume-staging' || exit
   docker volume rm 'b-dodeka-backup-volume-recover-staging' || exit
fi

# Run the docker-compose.yml
# -d for detached/background
docker compose pull && docker compose -p "${BACKUP_COMPOSE_PROJECT_NAME}" up -d

echo "Waiting 35 seconds before inspecting server startup..."
sleep 35

# Check if it is actually running by inspecting container state
# {{ is for jinja2 escaping
if [ "$( docker container inspect -f '{{.State.Status}}' b-dodeka-backup-1 )" = "running" ];
then
    echo "Barman startup successful."
else
    echo "Barman startup failed."
    # If fail, check logs
    docker container logs b-dodeka-backup-1
    # Shut down and remove
    ./down.sh
    # Exit code 1 indicates failure
    exit 1
fi