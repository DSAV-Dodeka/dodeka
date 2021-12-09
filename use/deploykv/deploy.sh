#!/bin/bash
# $0 is argument 0, which is always the script path
# % is a type of Parameter Expansion
# '/*' matches the last '/' and so %/* will remove everything after it
# This changes the directory to the directory containing the script
CUR_DIR="${0%/*}"
cd "$CUR_DIR" || exit
# This ensures all env variables are exported so env variables used in .env.deploy (like $HOME) are
# properly expanded
# env files are consumed by e.g. docker compose
set -a
# Load environment variables from .env.deploy file
. ./.env.deploy

# Run the docker-compose.yml
# -d for detached/background
docker compose -p "${KV_COMPOSE_PROJECT_NAME}" up -d

# Check if it is actually running by inspecting container state
if [ "$( docker container inspect -f '{{.State.Status}}' ts-dodeka-kv-1 )" == "running" ];
then
    echo "Redis startup successful."
    # Copy deploy to new directory to make it easy to shut down
    # -a preserves file information
    if [ "$1" = "move" ]; then
        cp -a "$CUR_DIR" ~/active_deploykv/
    fi
else
    echo "Redis startup failed."
    # If fail, check logs
    docker container logs ts-dodeka-kv-1
    # Shut down and remove
    ./down.sh
    # Exit code 1 indicates failure
    exit 1
fi