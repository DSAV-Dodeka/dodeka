#!/bin/bash
# First argument is either 'move' (cp to activedeploy) or anything else (no cp)
# Second argument is path for .env file to load (absolute or relative to this script!)

# $0 is argument 0, which is always the script path
# % is a type of Parameter Expansion
# '/*' matches the last '/' and so %/* will remove everything after it
# This changes the directory to the directory containing the script
cd "${0%/*}" || exit
# pwd is print working directory, -P ensures any links/shortcuts are resolved
CUR_DIR=$(pwd -P)
# This ensures all env variables are exported so env variables used in deploy.env (like $HOME) are
# properly expanded
# env files are consumed by e.g. docker compose
set -a
# Load environment variables from deploy.env file
. ./deploy.env

# -n means string is not null
if [ -n "$2" ]; then
  # ignore warning
  # shellcheck source=/dev/null
  # load additional env file, i.e. for final dev or deploy such as passwords
  . "$2"
fi

# Create the directory that will serve as the source for the container volume
# -p ensures parent directories are created and there is no error if it already exists
mkdir -p "${DB_RESOURCES_SOURCE}"

# Run the docker-compose.yml
# -d for detached/background
docker compose pull && docker compose -p "${DB_COMPOSE_PROJECT_NAME}" up -d

# Check if it is actually running by inspecting container state
if [ "$( docker container inspect -f '{{.State.Status}}' d-dodeka-db-1 )" = "running" ];
then
    echo "PostgreSQL startup successful."
    # Copy deploy to new directory to make it easy to shut down
    # -a preserves file information
    if [ "$1" = "move" ]; then
        rm -rf ~/active_deploydb
        touch "deployed$DEPLOYID.txt"
        cp -a "$CUR_DIR" ~/active_deploydb/
        echo "Deployment moved to ~/active_deploydb"
    fi
else
    echo "PostgreSQL startup failed."
    # If fail, check logs
    docker container logs d-dodeka-db-1
    # Shut down and remove
    ./down.sh
    # Exit code 1 indicates failure
    exit 1
fi