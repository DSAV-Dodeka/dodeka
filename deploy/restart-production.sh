#!/usr/bin/env bash
set -euf -o pipefail

echo "Restarting production services (auth first, then backend)..."
sudo systemctl restart dodeka-auth-production
sudo systemctl restart dodeka-backend-production
echo "Done."
