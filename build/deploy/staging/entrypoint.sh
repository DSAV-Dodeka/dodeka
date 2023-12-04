#!/bin/sh
export COMPOSE_PROJECT_NAME="{{ main.project }}${DEPLOY_NAME}"
export NETWORK_NAME="{{ main.docker_net_name }}${DEPLOY_NAME}"
docker compose --env-file staging.env --profile all pull
docker compose --env-file staging.env --profile all up -d