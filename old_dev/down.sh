#!/bin/sh
cd "${0%/*}" || exit
# This ensures all env variables are exported so env variables used in deploy.env (like $HOME) are
# properly expanded
# env files are consumed by e.g. docker compose
set -a
# Load environment variables from dev.env
. ./dev.env
./deploykv/down.sh
./deploydb/down.sh