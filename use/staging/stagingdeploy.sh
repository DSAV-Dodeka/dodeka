#!/bin/sh
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
set -a

# Start database
# 'rv' indicates remove volume, so database is started from scratch
./db/deploy.sh "$CUR_DIR"/staging.env rv || exit
./kv/deploy.sh "$CUR_DIR"/staging.env || exit
./server/deploy.sh "$CUR_DIR"/staging.env || exit