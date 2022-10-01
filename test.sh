#!/bin/bash
set -e
PASSPHRASE=$(python3 -c 'import pull as p; p.passphrase()')
ENV=$(python3 -c 'import pull as p; p.env()')
DEPLOYID="$(date +%s)"
gh repo clone DSAV-Dodeka/secrets ./secrets"$DEPLOYID"
python3 -c "import pull as p; p.move(${DEPLOYID}, ${ENV})"

echo "hi"