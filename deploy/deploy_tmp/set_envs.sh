#!/bin/bash

# Define the names of the environment variables
ENV_VARS=("POSTGRES_PASSWORD" "POSTGRES_USER" "REDIS_PASSWORD")

echo "Please enter values for the following environment variables:"
for VAR in "${ENV_VARS[@]}"; do
    read -p "Enter value for $VAR: " VALUE
    export "$VAR=$VALUE"
done

echo "Environment variables have been set in your current shell."