#!/bin/bash

# Only works if run from the deploy_tmp dir!

set -a

cd ../../authpage
echo "VITE_AUTHPAGE_AUTH_URL=https://api.dsavdodeka.nl" > .env.production
echo "VITE_AUTHPAGE_CLIENT_URL=https://demo.tipten.nl" >> .env.production
npm ci --force
npm run build -- --mode production --emptyOutDir

cd ../backend/deploy_tmp

cp -f ./define.toml ../src/apiserver/resources/define.toml
cp -f ./env.toml ../src/apiserver/resources/env.toml