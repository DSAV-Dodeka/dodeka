"""CLI for dev process management.

Usage: uv run dev-actions <command>
       uv run da <command>

Run 'uv run dev-actions --help' for a list of available commands.
"""

import argparse

import requests

from apiserver.settings import DEFAULT_DEV_CONTROL_PORT, PRIVATE_HOST

DEV_CONTROL_URL = f"http://{PRIVATE_HOST}:{DEFAULT_DEV_CONTROL_PORT}"


def cmd_restart(args: argparse.Namespace) -> None:
    """Send a restart command to the dev process."""
    try:
        response = requests.post(f"{DEV_CONTROL_URL}/restart", timeout=5)
        print(response.text)
    except requests.exceptions.ConnectionError:
        print("Dev process not running (could not connect).")


def cmd_stop(args: argparse.Namespace) -> None:
    """Send a stop command to the dev process."""
    try:
        response = requests.post(f"{DEV_CONTROL_URL}/stop", timeout=5)
        print(response.text)
    except requests.exceptions.ConnectionError:
        print("Dev process not running (could not connect).")


def cmd_status(args: argparse.Namespace) -> None:
    """Check if the dev process is running."""
    try:
        requests.get(f"{DEV_CONTROL_URL}/status", timeout=5)
        print("Dev process is running.")
    except requests.exceptions.ConnectionError:
        print("Dev process is not running.")


def create_dev_parser() -> argparse.ArgumentParser:
    """Create the argument parser for dev-actions commands."""
    parser = argparse.ArgumentParser(
        prog="dev-actions",
        description="Dev process management commands",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    restart_parser = subparsers.add_parser(
        "restart",
        help="Restart both servers (reloads code from disk)",
    )
    restart_parser.set_defaults(func=cmd_restart)

    stop_parser = subparsers.add_parser("stop", help="Gracefully stop the dev process")
    stop_parser.set_defaults(func=cmd_stop)

    status_parser = subparsers.add_parser(
        "status", help="Check if the dev process is running"
    )
    status_parser.set_defaults(func=cmd_status)

    return parser


def main() -> None:
    """Main CLI entry point."""
    parser = create_dev_parser()
    args = parser.parse_args()
    args.func(args)
