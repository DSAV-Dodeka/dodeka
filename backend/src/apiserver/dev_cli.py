"""CLI for dev process management.

Usage: uv run dev-actions <command>
       uv run da <command>

Run 'uv run dev-actions --help' for a list of available commands.
"""

import argparse
import os
import signal
from pathlib import Path

PID_FILE = Path("envs/test/dev.pid")


def read_dev_pid() -> int | None:
    """Read the dev process PID from the PID file.

    Returns None if the file doesn't exist, is invalid, or the process
    is no longer running.
    """
    if not PID_FILE.exists():
        return None
    try:
        pid = int(PID_FILE.read_text().strip())
        # Verify the process exists
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError):
        return None


def cmd_restart(args: argparse.Namespace) -> None:
    """Send SIGHUP to the dev process to trigger a restart."""
    pid = read_dev_pid()
    if pid is None:
        print(f"Dev process not running (no valid PID in {PID_FILE}).")
        return
    os.kill(pid, signal.SIGHUP)
    print(f"Restart signal sent to dev process (PID {pid}).")


def cmd_stop(args: argparse.Namespace) -> None:
    """Send SIGTERM to the dev process for graceful shutdown."""
    pid = read_dev_pid()
    if pid is None:
        print(f"Dev process not running (no valid PID in {PID_FILE}).")
        return
    os.kill(pid, signal.SIGTERM)
    print(f"Stop signal sent to dev process (PID {pid}).")


def cmd_status(args: argparse.Namespace) -> None:
    """Check if the dev process is running."""
    pid = read_dev_pid()
    if pid is None:
        print("Dev process is not running.")
    else:
        print(f"Dev process is running (PID {pid}).")


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
