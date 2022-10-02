#!/bin/sh
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
set -a

if [ "$1" = "update" ]
then
  export RECREATE=no
  ./db/deploy.sh "$CUR_DIR"/staging.env || exit
else
  # Everything must be down for recreation and removing volume
  ./down.sh
  # 'rv' indicates remove volume, so database is started from scratch
  ./db/deploy.sh "$CUR_DIR"/staging.env rv || exit
fi

./kv/deploy.sh "$CUR_DIR"/staging.env || exit
./server/deploy.sh "$CUR_DIR"/staging.env || exit