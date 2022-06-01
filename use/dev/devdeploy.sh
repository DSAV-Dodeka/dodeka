#!/bin/sh
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
set -a

# Load dev environment variables from .env.deploy file
echo "$CUR_DIR"/dev.env
# Start database, then key-value store
./deploydb/deploy.sh nomove "$CUR_DIR"/dev.env || exit
./deploykv/deploy.sh nomove "$CUR_DIR"/dev.env || exit