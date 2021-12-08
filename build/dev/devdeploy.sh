#!/bin/sh
cd "${0%/*}" || exit
set -a

# Load dev environment variables from .env.deploy file
. ./dev.env
# Start database, then key-value store
./deploydb/deploy.sh
./deploykv/deploy.sh