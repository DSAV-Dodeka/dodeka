#!/bin/sh
export DEPLOY_NAME="staging-${TIDPLOY_TAG}"
export COMPOSE_PROJECT_NAME="{{ main.project }}-${DEPLOY_NAME}"
export NETWORK_NAME="{{ main.docker_net_name }}-${DEPLOY_NAME}"
export KV_VERSION=staging-${TIDPLOY_SHA}
export DB_VERSION=staging-${TIDPLOY_SHA}
export SERVER_VERSION=staging-${TIDPLOY_SHA}
docker compose --env-file staging.env --profile all pull
docker compose --env-file staging.env --profile all up -d