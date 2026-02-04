#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

install_env() {
    local env="$1"
    echo "Installing $env environment services..."

    echo "  Copying service files to /etc/systemd/system/..."
    sudo cp "$SCRIPT_DIR/dodeka-auth-$env.service" /etc/systemd/system/
    sudo cp "$SCRIPT_DIR/dodeka-backend-$env.service" /etc/systemd/system/

    echo "  Enabling services..."
    sudo systemctl enable "dodeka-auth-$env.service"
    sudo systemctl enable "dodeka-backend-$env.service"
}

ENV="${1:-all}"

case "$ENV" in
    demo)
        install_env demo
        ;;
    production)
        install_env production
        ;;
    all)
        install_env demo
        install_env production
        ;;
    *)
        echo "Usage: $0 [demo|production|all]"
        echo "  demo        - Install demo environment services"
        echo "  production  - Install production environment services"
        echo "  all         - Install both environments (default)"
        exit 1
        ;;
esac

echo ""
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

echo ""
echo "Done! To start services:"
echo "  sudo systemctl start dodeka-auth-demo dodeka-backend-demo"
echo "  sudo systemctl start dodeka-auth-production dodeka-backend-production"
echo ""
echo "To check status:"
echo "  sudo systemctl status dodeka-auth-demo dodeka-backend-demo"
echo "  sudo systemctl status dodeka-auth-production dodeka-backend-production"
echo ""
echo "To view logs:"
echo "  journalctl -u dodeka-auth-demo -u dodeka-backend-demo -f"
echo "  journalctl -u dodeka-auth-production -u dodeka-backend-production -f"
