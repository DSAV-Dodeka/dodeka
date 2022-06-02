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
# This ensures all env variables are exported so env variables used in .env.deploy (like $HOME) are
# properly expanded
# env files are consumed by e.g. docker compose
set -a
# Load environment variables from .env.deploy file
. ./deploy.env

# Run the docker-compose.yml
# -d for detached/background
docker compose -p "${SERVER_COMPOSE_PROJECT_NAME}" up -d

echo "Waiting 5 seconds before inspecting server startup..."
sleep 5
# Check if it is actually running by inspecting container state
if [ "$( docker container inspect -f '{{.State.Status}}' s-dodeka-server-1 )" = "running" ];
then
    echo "Backend startup successful."
    if [ "$1" = "move" ]; then
        rm -rf ~/active_deployserver
        touch "deployed$DEPLOYID.txt"
        cp -a "$CUR_DIR" ~/active_deployserver/
        echo "Deployment moved to ~/active_deployserver"
    fi
else
    echo "Backend startup failed."
    # If fail, check logs
    docker container logs s-dodeka-server-1
    # Shut down and remove
    ./down.sh
    # Exit code 1 indicates failure
    exit 1
fi