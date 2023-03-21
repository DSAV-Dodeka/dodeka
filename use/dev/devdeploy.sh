#!/bin/sh
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
set -a

# Load dev environment variables from dev.env file
# The 'port' option indicates to use the dev_env with the changed port
# This is necessary on WSL where you cannot expose to just localhost
if [ "$1" = "port" ] || [ "$2" = "port" ]
then
  DEV_ENV="$CUR_DIR"/dev_port.env
else
  DEV_ENV="$CUR_DIR"/dev.env
fi

echo "$DEV_ENV"
# Start database, then key-value store
./db/deploy.sh "$DEV_ENV" || exit
./kv/deploy.sh "$DEV_ENV" || exit

# By default, the server is not started as it is generally run from Python in development
if [ "$1" = "server" ]
then
  ./server/deploy.sh "$DEV_ENV" || exit
fi