#!/bin/bash
# $0 is argument 0, which is always the script path
# % is a type of Parameter Expansion
# '/*' matches the last '/' and so %/* will remove everything after it
# This changes the directory to the directory containing the script
CUR_DIR="${0%/*}"
cd "$CUR_DIR" || exit
# This ensures all env variables are exported so env variables used in .env.db (like $HOME) are
# properly expanded
# env files are consumed by e.g. docker compose
set -a
# Load environment variables from .env.db file
. ./.env.deploy
# Create the directory that will serve as the source for the container volume
# -p ensures parent directories are created and there is no error if it already exists
mkdir -p "${RESOURCES_SOURCE}"

# Run the docker-compose.yml
# -d for detached/background
docker compose up -d

# Check if it is actually running by inspecting container state
if [ "$( docker container inspect -f '{{.State.Status}}' ~spwn@container_name@~ )" == "running" ];
then
    echo "PostgreSQL startup successful."
    # Copy deploy to new directory to make it easy to shut down
    # -a preserves file information
    cp -a "$CUR_DIR" ~/active_deploy/
else
    echo "PostgreSQL startup failed."
    # If fail, check logs
    docker container logs ~spwn@container_name@~
    # Shut down and remove
    ./down.sh
    # Exit code 1 indicates failure
    exit 1
fi