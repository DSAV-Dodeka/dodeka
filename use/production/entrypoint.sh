#!/bin/sh
export COMPOSE_PROJECT_NAME="dodeka${DEPLOY_NAME}"
export NETWORK_NAME="dodeka${DEPLOY_NAME}"
docker compose --profile all pull
docker compose --profile all up -d