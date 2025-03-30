#!/bin/bash

# Define the names of the environment variables
ENV_VARS=("DB_PASS" "KV_PASS" "MAIL_PASS" "KEY_PASS")

echo "Please enter values for the following environment variables:"
for VAR in "${ENV_VARS[@]}"; do
    read -p "Enter value for $VAR: " VALUE
    export "$VAR=$VALUE"
done

. ./.env

echo "Environment variables have been set in your current shell."