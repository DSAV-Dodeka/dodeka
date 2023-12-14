#!/bin/bash
# we want to auto-export all environment variables we set so docker compose can use them
set -a
echo "Waiting for secrets..."
while [ true ] 
do 
    # if file exists and is named pipe
    if [ -p "$1" ]; then
        . $1
        if [ -n "$TIDPLOY_READY" ]; then
            echo "Starting...."
            ./entrypoint.sh
            break
        else
            echo "Secrets loaded."
        fi
    # if pipe doesn't exist we don't want to run too many loops
    else
        sleep 1
    fi
done