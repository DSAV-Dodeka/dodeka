"""CLI for the backend private server.

Usage: uv run backend-actions <command> [args]

Run 'uv run backend-actions --help' for a list of available commands.
"""

from apiserver.tooling.commands import configure_private_port, create_backend_parser


def main() -> None:
    """Main CLI entry point."""
    parser = create_backend_parser()
    args = parser.parse_args()
    try:
        configure_private_port(args.env, args.env_file)
    except FileNotFoundError as exc:
        parser.error(str(exc))
    args.func(args)


if __name__ == "__main__":
    main()
