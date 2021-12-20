#!/bin/sh
# $0 is argument 0, which is always the script path
# % is a type of Parameter Expansion
# '/*' matches the last '/' and so %/* will remove everything after it
# This changes the directory to the directory containing the script
cd "${0%/*}" || exit
# This ensures all env variables are exported so env variables used in .env.deploy (like $HOME) are properly expanded when the
# env files are consumed by e.g. docker compose
set -a
# Load environment variables from .env.deploy file
. ./.env.deploy

# Removes volumes
docker compose -p "${KV_COMPOSE_PROJECT_NAME}" down -v