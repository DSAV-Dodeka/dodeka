#!/bin/sh
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
set -a

echo "Running repl deploy script with argument $1"

./db/deploy.sh "$CUR_DIR"/repl.env || exit