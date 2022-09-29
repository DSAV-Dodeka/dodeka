#!/bin/bash
# First argument is either 'move' (cp to activedeploy) or anything else (no cp)
# Second argument is path for .env file to load (absolute or relative to this script!)

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

# Moves the configuration file in temporarily with password
# Password must be an env variable set externally
mkdir -p ./conf
cp ./redis_nopass.conf ./conf/redis.conf
echo "requirepass ${REDIS_PASSWORD}" >> ./conf/redis.conf

# Run the docker-compose.yml
# -d for detached/background
docker compose pull && docker compose -p "${KV_COMPOSE_PROJECT_NAME}" up -d

echo "Waiting 1 second before inspecting Redis startup..."
sleep 1
# Check if it is actually running by inspecting container state
# {{ '{{' }} is for jinja2 escaping
if [ "$( docker container inspect -f '{{ '{{' }}.State.Status{{ '}}' }}' {{ kv.container_name }} )" == "running" ];
then
    echo "Redis startup successful."
else
    echo "Redis startup failed."
    # If fail, check logs
    docker container logs {{ kv.container_name }}
    # Shut down and remove
    ./down.sh
    # Exit code 1 indicates failure
    exit 1
fi

# Remove the conf file so password is not easily visible
rm -r ./conf