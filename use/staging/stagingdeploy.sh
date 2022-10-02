#!/bin/sh
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
set -a

echo "Running staging deploy script with argument $1"

if [ "$1" = "update" ]
then
  ./db/deploy.sh "$CUR_DIR"/staging.env || exit
  ./kv/deploy.sh "$CUR_DIR"/staging.env || exit
  ./server/deploy.sh "$CUR_DIR"/staging.env || exit
else
  echo "Shutting down and recreating database..."
  # Everything must be down for recreation and removing volume
  ./down.sh
  # 'rv' indicates remove volume, so database is started from scratch
  ./db/deploy.sh "$CUR_DIR"/restaging.env rv || exit
  ./kv/deploy.sh "$CUR_DIR"/restaging.env || exit
  ./server/deploy.sh "$CUR_DIR"/restaging.env || exit
fi
