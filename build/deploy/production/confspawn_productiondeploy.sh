#!/bin/sh
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
set -a

echo "Running production deploy script with argument $1"

if [ "$1" = "recreate" ]
then
  echo "Shutting down and recreating database..."
  # Everything must be down for recreation and removing volume
  ./down.sh
  # 'rv' indicates remove volume, so database is started from scratch
  ./db/deploy.sh "$CUR_DIR"/recproduction.env rv || exit
  ./kv/deploy.sh "$CUR_DIR"/recproduction.env || exit
  ./server/deploy.sh "$CUR_DIR"/recproduction.env || exit
else
  ./db/deploy.sh "$CUR_DIR"/production.env || exit
  ./kv/deploy.sh "$CUR_DIR"/production.env || exit
  ./server/deploy.sh "$CUR_DIR"/production.env || exit
fi

