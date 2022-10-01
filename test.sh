#!/bin/bash
echo "Setting up deployment in $ENV_STR mode..."
set -e
cd "${0%/*}" || exit
CUR_DIR=$(pwd -P)
PASSPHRASE=$(python3 -c 'import pull as p; p.passphrase()')
ENV_STR="$1"
DEPLOYID="$(date +%s)"
echo "Current time: $DEPLOYID"
SECRET_TARGET="./deployments/${ENV_STR}/secrets${DEPLOYID}"
gh repo clone DSAV-Dodeka/secrets "$SECRET_TARGET"
rm -rf "$SECRET_TARGET/.git"
python3 -c "import pull as p; p.move('${DEPLOYID}', '${ENV_STR}')"
cd "$SECRET_TARGET"
echo "Decrypting..."
set -a
. decrypt.sh secretdb.env.gpg "$PASSPHRASE" || exit 1
. decrypt.sh secretserver.env.gpg "$PASSPHRASE" || exit 1
# TODO check existence?
cd "$CUR_DIR/deployments/active$ENV_STR"
echo "Running..."
"./${ENV_STR}deploy.sh"