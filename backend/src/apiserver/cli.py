"""CLI for the backend private server.

Commands:
- reset: clear all tables and re-bootstrap admin
- prepare-user: create user ready for tiauth-faroe signup flow (testing)
- get-admin-credentials: return bootstrapped admin email/password
- get-token: retrieve email verification code (for test automation)

The private server also handles:
- POST /invoke: user action invocation from tiauth-faroe
- POST /email: email sending (stores tokens for testing, sends via SMTP if configured)
"""

import argparse
from typing import Any

import requests

from apiserver.settings import DEFAULT_PRIVATE_PORT, PRIVATE_HOST


def get_private_url(port: int = DEFAULT_PRIVATE_PORT) -> str:
    """Get the base URL for the private server."""
    return f"http://{PRIVATE_HOST}:{port}"


def send_command(command: str, **kwargs: Any) -> str:
    """Send a command to the running server via HTTP."""
    url = f"{get_private_url()}/command"
    payload = {"command": command, **kwargs}

    try:
        response = requests.post(url, json=payload, timeout=30)
        return response.text
    except requests.exceptions.ConnectionError:
        return f"Error: Could not connect to {url}. Is the server running?"


def cmd_reset(_args: argparse.Namespace) -> None:
    """Clear all tables and re-bootstrap admin."""
    result = send_command("reset")
    print(result)


def cmd_prepare_user(args: argparse.Namespace) -> None:
    """Prepare a user in the newusers table with accepted=True."""
    names = []
    if args.firstname:
        names.append(args.firstname)
    if args.lastname:
        names.append(args.lastname)

    result = send_command("prepare_user", email=args.email, names=names)
    print(result)


def cmd_get_admin_credentials(_args: argparse.Namespace) -> None:
    """Get the bootstrap admin credentials."""
    result = send_command("get_admin_credentials")
    print(result)


def cmd_get_token(args: argparse.Namespace) -> None:
    """Get an email verification token."""
    result = send_command("get_token", action=args.action, email=args.email)
    print(result)


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="backend-actions",
        description="CLI for communicating with a running backend server",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # reset command
    reset_parser = subparsers.add_parser(
        "reset", help="Clear all tables and re-bootstrap admin"
    )
    reset_parser.set_defaults(func=cmd_reset)

    # prepare-user command
    prepare_parser = subparsers.add_parser(
        "prepare-user", help="Prepare a user in the newusers table with accepted=True"
    )
    prepare_parser.add_argument("email", help="Email address of the user")
    prepare_parser.add_argument("--firstname", "-f", help="First name of the user")
    prepare_parser.add_argument("--lastname", "-l", help="Last name of the user")
    prepare_parser.set_defaults(func=cmd_prepare_user)

    # get-admin-credentials command
    admin_creds_parser = subparsers.add_parser(
        "get-admin-credentials", help="Get the bootstrap admin credentials"
    )
    admin_creds_parser.set_defaults(func=cmd_get_admin_credentials)

    # get-token command
    token_parser = subparsers.add_parser(
        "get-token", help="Get an email verification token"
    )
    token_parser.add_argument("action", help="Token action (e.g., signup, reset)")
    token_parser.add_argument("email", help="Email address")
    token_parser.set_defaults(func=cmd_get_token)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
