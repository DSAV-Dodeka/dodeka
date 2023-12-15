#!/bin/sh
export COMPOSE_PROJECT_NAME="{{ main.project }}-${TIDPLOY_TAG}"
export NETWORK_NAME="{{ main.docker_net_name }}-${TIDPLOY_TAG}"
export KV_VERSION=staging-${TIDPLOY_SHA}
export DB_VERSION=staging-${TIDPLOY_SHA}
export SERVER_VERSION=staging-${TIDPLOY_SHA}
docker compose --env-file staging.env --profile all pull
docker compose --env-file staging.env --profile all up -d