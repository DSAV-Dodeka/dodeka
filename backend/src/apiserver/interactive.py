"""Interactive shell for the backend server."""

import logging
import sys
import threading
from typing import Callable

from freetser import Storage
from freetser.server import StorageQueue

from apiserver.private import TOKENS_TABLE

logger = logging.getLogger("apiserver.interactive")


class InteractiveShell:
    """Simple interactive shell for server management."""

    def __init__(
        self,
        store_queue: StorageQueue,
        reset_callback: Callable[[], str],
    ):
        self.store_queue = store_queue
        self.reset_callback = reset_callback
        self._stop = False

    def start(self) -> None:
        """Start the interactive shell in a background thread."""
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()

    def _run(self) -> None:
        """Run the interactive shell loop."""
        print("Interactive mode started.")
        print("Type 'help' for available commands.")
        print("> ", end="", flush=True)

        while not self._stop:
            try:
                line = sys.stdin.readline()
                if not line:
                    break
                command = line.strip()
                self._handle_command(command)
            except EOFError:
                break
            except Exception as e:
                logger.error(f"Interactive shell error: {e}")

    def _handle_command(self, command: str) -> None:
        """Handle a single command."""
        if command == "reset":
            self._do_reset()
        elif command == "help":
            self._show_help()
        elif command in ("exit", "quit"):
            print("Exiting...")
            sys.exit(0)
        elif command == "":
            pass
        else:
            print(f"Unknown command: {command} (type 'help' for available commands)")

        print("> ", end="", flush=True)

    def _show_help(self) -> None:
        """Show available commands."""
        print("Available commands:")
        print("  reset - Clear all tables and re-bootstrap admin")
        print("  help  - Show this help message")
        print("  exit  - Exit program")

    def _do_reset(self) -> None:
        """Clear all tables and re-bootstrap admin."""
        tables = [
            "users",
            "users_by_email",
            "newusers",
            "registration_state",
            "metadata",
            "session_cache",
            TOKENS_TABLE,
        ]

        def clear_tables(store: Storage) -> None:
            for table in tables:
                store.clear(table)

        self.store_queue.execute(clear_tables)
        print("Tables cleared.")

        # Re-bootstrap admin
        print("Re-bootstrapping admin...")
        try:
            self.reset_callback()
            print("Admin re-bootstrapped successfully.")
        except Exception as e:
            print(f"Failed to re-bootstrap admin: {e}")
