#!/usr/bin/env bash
set -euf -o pipefail

echo "Restarting demo services (auth first, then backend)..."
sudo systemctl restart dodeka-auth-demo
sudo systemctl restart dodeka-backend-demo
echo "Done."
