#!/bin/bash

# Only works if run from the deploy_tmp dir!

set -a

cd ../../authpage
echo "VITE_AUTHPAGE_AUTH_URL=https://api.dsavdodeka.nl" > .env.production
echo "VITE_AUTHPAGE_CLIENT_URL=https://dsavdodeka.nl" >> .env.production
npm ci
npm run build -- --mode production

cd ../../deploy_tmp

mv -f ./define.toml ../src/apiserver/resources/define.toml
mv -f ./env.toml ../src/apiserver/resources/env.toml

# Define the names of the environment variables
ENV_VARS=("DB_PASS" "KV_PASS" "MAIL_PASS", "KEY_PASS")

echo "Please enter values for the following environment variables:"
for VAR in "${ENV_VARS[@]}"; do
    read -p "Enter value for $VAR: " VALUE
    export "$VAR=$VALUE"
done

source .env

echo "Environment variables have been set in your current shell."