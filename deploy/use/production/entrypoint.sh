#!/bin/sh
export DEPLOY_NAME="production-${TIDPLOY_TAG}"
export COMPOSE_PROJECT_NAME="dodeka-${DEPLOY_NAME}"
export NETWORK_NAME="dodeka-${DEPLOY_NAME}"
export KV_VERSION="${TIDPLOY_SHA}"
export DB_VERSION="${TIDPLOY_SHA}"
export SERVER_VERSION="${TIDPLOY_SHA}"
docker compose --env-file production.env --profile all pull
docker compose --env-file production.env --profile all up -d