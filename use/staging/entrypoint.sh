#!/bin/sh
export COMPOSE_PROJECT_NAME="dodeka-${DEPLOY_NAME}"
export NETWORK_NAME="dodeka-${DEPLOY_NAME}"
docker compose --env-file staging.env --profile all pull
docker compose --env-file staging.env --profile all up -d