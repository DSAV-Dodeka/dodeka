#!/bin/sh
export COMPOSE_PROJECT_NAME="{{ main.project }}${DEPLOY_NAME}"
export NETWORK_NAME="{{ main.docker_net_name }}${DEPLOY_NAME}"
docker compose --profile all pull
docker compose --profile all up -d