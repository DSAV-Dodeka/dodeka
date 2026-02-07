"""CLI for the backend private server.

Usage: uv run backend-actions <command> [args]

Run 'uv run backend-actions --help' for a list of available commands.
"""

from apiserver.commands import create_backend_parser


def main() -> None:
    """Main CLI entry point."""
    parser = create_backend_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
