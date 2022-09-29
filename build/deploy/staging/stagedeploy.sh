#!/bin/sh
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
set -a

# Start database
./db/deploy.sh nomove "$CUR_DIR"/staging.env || exit