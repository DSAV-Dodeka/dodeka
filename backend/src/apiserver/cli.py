"""CLI commands that communicate with a running backend server."""

import argparse
import json
import socket
from typing import Any

from apiserver.settings import settings


def send_command(command: str, **kwargs: Any) -> str:
    """Send a command to the running server via UDS."""
    socket_path = str(settings.socket_path)

    # Create UDS connection
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(socket_path)
    except FileNotFoundError:
        return f"Error: Socket not found at {socket_path}. Is the server running?"
    except ConnectionRefusedError:
        return f"Error: Connection refused at {socket_path}. Is the server running?"

    # Build HTTP request
    body = json.dumps({"command": command, **kwargs})
    request = (
        f"POST /command HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"\r\n"
        f"{body}"
    )

    try:
        sock.sendall(request.encode("utf-8"))

        # Read response
        response = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
            # Check if we've received the full response
            if b"\r\n\r\n" in response:
                # Parse headers to get content length
                header_end = response.index(b"\r\n\r\n")
                headers = response[:header_end].decode("utf-8")
                body_start = header_end + 4

                # Find content-length
                content_length = 0
                for line in headers.split("\r\n"):
                    if line.lower().startswith("content-length:"):
                        content_length = int(line.split(":")[1].strip())
                        break

                # Check if we have the full body
                if len(response) >= body_start + content_length:
                    break

        # Parse response
        if b"\r\n\r\n" in response:
            header_end = response.index(b"\r\n\r\n")
            body = response[header_end + 4 :].decode("utf-8")
            return body
        return response.decode("utf-8")
    finally:
        sock.close()


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

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
