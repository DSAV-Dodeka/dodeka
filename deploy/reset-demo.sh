#!/usr/bin/env bash
set -euf -o pipefail

echo "Stopping demo services..."
sudo systemctl stop dodeka-backend-demo
sudo systemctl stop dodeka-auth-demo

echo "Removing demo database files..."
rm -f /home/backend/dodeka/backend/envs/demo/db.sqlite*
rm -f /home/backend/dodeka/backend/auth/envs/demo/db.sqlite*

echo "Starting demo services (auth first, then backend)..."
sudo systemctl start dodeka-auth-demo
sudo systemctl start dodeka-backend-demo
echo "Done. Demo has been reset with clean databases."
