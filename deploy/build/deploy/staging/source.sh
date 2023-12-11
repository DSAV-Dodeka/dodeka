#!/bin/bash
set -a
echo "Waiting for secrets..."
while [ true ] 
do 
    # if file exists and is named pipe
    if [ -p "$1" ]; then
        . $1
    else
        sleep 1
    fi

    if [ -n "$TIDPLOY_READY" ]; then
        echo "Starting...."
        ./entrypoint.sh
        break
    fi
done

echo "done!"