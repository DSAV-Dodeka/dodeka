#!/bin/bash
rm -f deploypipe
mkfifo deploypipe
docker run -v ./deploypipe:/deployer/ti_dploy_pipe -v ./deploy.json:/deployer/deploy.json ghcr.io/tiptenbrink/bws-dployer:latest & ./source.sh ./deploypipe
rm deploypipe