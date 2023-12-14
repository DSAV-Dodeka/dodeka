#!/bin/bash

cleanup() {
    echo
    echo "Removing pipe..."
    rm -f deploypipe
    exit 1
}

# if you do Ctrl+C it will run cleanup
trap cleanup SIGINT

# remove the pipe if it somehow still exists
rm -f deploypipe
# create a named fifo pipe at ./deploypipe
mkfifo deploypipe
# run the deployer, providing it with the Secrets Manager access token and
# mounting the named pipe as well as the JSON containing the secrets to the 
# container
# the process is started in the background (the '&') and then we run our 
# previous script with the name of the pipe as the first argument
docker run \
  -e BWS_ACCESS_TOKEN \
  -v ./deploypipe:/dployer/ti_dploy_pipe \
  -v "./tidploy.json:/dployer/tidploy.json" \
  ghcr.io/tiptenbrink/bws-dployer:latest & \
./source.sh ./deploypipe
# finally we clean up the pipe by removing it
rm deploypipe