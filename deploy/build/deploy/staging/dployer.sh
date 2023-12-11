#!/bin/bash
rm -f deploypipe
mkfifo deploypipe
docker run -e BWS_ACCESS_TOKEN -v ./deploypipe:/dployer/ti_dploy_pipe -v ./tidploy.json:/dployer/tidploy.json ghcr.io/tiptenbrink/bws-dployer:latest & ./source.sh ./deploypipe
rm deploypipe