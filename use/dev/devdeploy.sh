#!/bin/sh
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
set -a

# Load dev environment variables from dev.env file
echo "$CUR_DIR"/dev.env
# Start database, then key-value store
./db/deploy.sh "$CUR_DIR"/dev.env || exit
./kv/deploy.sh "$CUR_DIR"/dev.env || exit

# By default, the server is not started as it is generally run from Python in development
if [ "$1" = "server" ]
then
  ./server/deploy.sh "$CUR_DIR"/dev.env || exit
fi