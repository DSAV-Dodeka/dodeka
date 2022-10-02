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
if [ -n "$1" ]; then
  # ignore warning
  # shellcheck source=/dev/null
  # load additional env file, i.e. for final dev or deploy such as passwords
  . "$1"
fi

if [ "$1" = "rv" ]; then
   docker volume rm '{{ db.volume_name }}-{{ confspawn_env.name }}' || exit
fi

# Create the directory that will serve as the source for the container volume
# -p ensures parent directories are created and there is no error if it already exists
mkdir -p "${DB_RESOURCES_SOURCE}"

# Run the docker-compose.yml
# -d for detached/background
docker compose pull && docker compose -p "${DB_COMPOSE_PROJECT_NAME}" up -d

# Check if it is actually running by inspecting container state
# {{ '{{' }} is for jinja2 escaping
if [ "$( docker container inspect -f '{{ '{{' }}.State.Status{{ '}}' }}' {{ db.container_name }} )" = "running" ];
then
    echo "PostgreSQL startup successful."
else
    echo "PostgreSQL startup failed."
    # If fail, check logs
    docker container logs {{ db.container_name }}
    # Shut down and remove
    ./down.sh
    # Exit code 1 indicates failure
    exit 1
fi