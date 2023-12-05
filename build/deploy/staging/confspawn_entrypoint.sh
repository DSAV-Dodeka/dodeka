#!/bin/sh
export COMPOSE_PROJECT_NAME="{{ main.project }}-${DEPLOY_NAME}"
export NETWORK_NAME="{{ main.docker_net_name }}-${DEPLOY_NAME}"
export KV_VERSION=staging${DEPLOY_TAG_SUFFIX}
export DB_VERSION=staging${DEPLOY_TAG_SUFFIX}
export SERVER_VERSION=staging${DEPLOY_TAG_SUFFIX}
docker compose --env-file staging.env --profile all pull
docker compose --env-file staging.env --profile all up -d