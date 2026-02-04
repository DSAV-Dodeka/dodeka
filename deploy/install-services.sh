#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ENV="${1:-demo}"

if [[ "$ENV" != "demo" && "$ENV" != "production" ]]; then
    echo "Usage: $0 [demo|production]"
    echo "  demo        - Install demo environment services (default)"
    echo "  production  - Install production environment services"
    exit 1
fi

echo "Installing $ENV environment services..."

echo "Copying service files to /etc/systemd/system/..."
sudo cp "$SCRIPT_DIR/dodeka-auth-$ENV.service" /etc/systemd/system/
sudo cp "$SCRIPT_DIR/dodeka-backend-$ENV.service" /etc/systemd/system/

echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

echo "Enabling services..."
sudo systemctl enable "dodeka-auth-$ENV.service"
sudo systemctl enable "dodeka-backend-$ENV.service"

echo ""
echo "Done! To start the services:"
echo "  sudo systemctl start dodeka-auth-$ENV"
echo "  sudo systemctl start dodeka-backend-$ENV"
echo ""
echo "To check status:"
echo "  sudo systemctl status dodeka-auth-$ENV"
echo "  sudo systemctl status dodeka-backend-$ENV"
echo ""
echo "To view logs:"
echo "  journalctl -u dodeka-auth-$ENV -f"
echo "  journalctl -u dodeka-backend-$ENV -f"
