#!/bin/bash
# DEPLOYMENT SCRIPT designed for staging and production deployments on remote machines

# TO RUN THIS SCRIPT THERE ARE TWO IMPORTANT REQUIREMENTS:
# - logged in using gh to have access to secrets repository
# - logged in using Docker to ghcr.io to download packages
# - gpg must be installed
# - modern python3 must be available
# First argument is the environment mode ('staging', 'production', 'test')
# Second argument is passed to the deployment script
ENV_STR="$1"
DEPLOY_ARG="$2"
echo "Setting up deployment in $ENV_STR mode..."
# Exits if any error is encountered
set -e
# Changes to script directory location
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
# Uses Python getpass to request password
PASSPHRASE=$(python3 -c 'import pull as p; p.passphrase()')
# Unix timestamp in seconds
DEPLOYID="$(date +%s)"
echo "Current time: $DEPLOYID"
# Target for secrets repo
SECRET_TARGET="./deployments/${ENV_STR}/secrets${DEPLOYID}"
# Clone secrets history
gh repo clone DSAV-Dodeka/secrets "$SECRET_TARGET"
# We do not need to save any git history
rm -rf "$SECRET_TARGET/.git"
# We use Python to implement the directory move logic, as this is much more convenient than using shell scripts
# See pull/pull.py for explanation
# In short it:
# - Saves the current 'use' scripts as a history
# - Sets an 'active' directory inside ./deployments/<env>/ with the target 'use' scripts
# - Puts a copy of the secrets inside
python3 -c "import pull as p; p.move('${DEPLOYID}', '${ENV_STR}')"
# We move into the secrets directory
cd "$SECRET_TARGET"
echo "Decrypting..."
# We ensure that environment variables are exported
set -a
# We decrypt the server and database secrets using the supplied passphrase
. decrypt.sh secretdb.env.gpg "$PASSPHRASE" || exit 1
. decrypt.sh secretserver.env.gpg "$PASSPHRASE" || exit 1
cd "$CUR_DIR/deployments/active$ENV_STR"
echo "Running..."
# Run the deploy script
"./${ENV_STR}deploy.sh" "$DEPLOY_ARG"