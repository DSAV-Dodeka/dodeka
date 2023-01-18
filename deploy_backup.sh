#!/bin/bash

# Second argument is passed to the deployment script
ENV_STR="$1"
DEPLOY_ARG="$2"

# Changes to script directory location
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
# Unix timestamp in seconds
DEPLOYID="$(date +%s)"
# Export env variables
set -a
OVERRIDE_BARMAN_PASSWORD=$(python3 -c 'import pull as p; p.passphrase()')

python3 -c "import pull as p; p.move_backup('${DEPLOYID}', '${ENV_STR}')"

cd "$CUR_DIR/deployments/activebackup$ENV_STR"
echo "Running..."
# Run the deploy script
"./deploy.sh" "$DEPLOY_ARG"

