"""CLI for the auth server.

Usage: uv run auth-actions <command> [args]
       uv run aa <command> [args]

Run 'uv run auth-actions --help' for a list of available commands.
"""

import argparse
import json

import requests

from apiserver.settings import DEFAULT_AUTH_COMMAND_URL


def send_auth_command(command: str) -> str:
    """Send a command to the auth server via HTTP."""
    url = f"{DEFAULT_AUTH_COMMAND_URL}/command"
    payload = {"command": command}

    try:
        response = requests.post(url, json=payload, timeout=10)
        return response.text
    except requests.exceptions.ConnectionError:
        return f"Error: Could not connect to {url}. Is the auth server running?"


def send_auth_command_json(command: str) -> dict | None:
    """Send a command and parse JSON response."""
    url = f"{DEFAULT_AUTH_COMMAND_URL}/command"
    payload = {"command": command}

    try:
        response = requests.post(url, json=payload, timeout=10)
        return json.loads(response.text)
    except requests.exceptions.ConnectionError:
        print(f"Error: Could not connect to {url}. Is the auth server running?")
        return None
    except json.JSONDecodeError:
        print(f"Error: Invalid response: {response.text}")
        return None


def cmd_reset(args: argparse.Namespace) -> None:
    """Reset the auth server storage (clear all data)."""
    result = send_auth_command_json("reset")
    if result is None:
        return
    if result.get("success"):
        print(result.get("message", "Auth storage cleared."))
    elif "error" in result:
        print(f"Error: {result['error']}")
    else:
        print(result)


def create_auth_parser() -> argparse.ArgumentParser:
    """Create the argument parser for auth commands."""
    parser = argparse.ArgumentParser(
        prog="auth-actions",
        description="Auth server management commands",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    reset_parser = subparsers.add_parser("reset", help="Clear all auth server data")
    reset_parser.set_defaults(func=cmd_reset)

    return parser


def main() -> None:
    """Main CLI entry point."""
    parser = create_auth_parser()
    args = parser.parse_args()
    args.func(args)
