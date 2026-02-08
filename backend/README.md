# Dodeka Backend

## Installation

Install dependencies using the lockfile (production):

```bash
uv sync --frozen --no-dev
```

- `--frozen` - Use only the lockfile, don't resolve or update dependencies
- `--no-dev` - Exclude development dependencies

For development (includes linting/type checking tools):

```bash
uv sync --frozen
```

## Running

For local development (uses `.env.test`):

```bash
uv run dev
```

For demo environment (uses `.env.demo`):

```bash
uv run --frozen --no-dev demo
```

For production (uses `.env`):

```bash
uv run --frozen --no-dev production
```

With a custom env file:

```bash
uv run --frozen --no-dev backend --env-file /path/to/.env
```

## Configuration

Settings are loaded from `.env` files. Available environment variables:

- `BACKEND_DB_FILE` - Path to SQLite database (default: `./db.sqlite`)
- `BACKEND_ENVIRONMENT` - Environment mode: `test`, `demo`, or `production`
- `BACKEND_AUTH_SERVER_URL` - URL of Go auth server (default: `http://localhost:12770`)
- `BACKEND_FRONTEND_ORIGIN` - Frontend origin for CORS
- `BACKEND_DEBUG_LOGS` - Enable debug logging (`true`/`false`)
- `BACKEND_PORT` - Port for public API (default: `12780`)
- `BACKEND_PRIVATE_PORT` - Port for Go-Python communication (default: `12790`)

SMTP settings (optional):

- `BACKEND_SMTP_HOST` - SMTP server hostname
- `BACKEND_SMTP_PORT` - SMTP server port
- `BACKEND_SMTP_SENDER_EMAIL` - Sender email address
- `BACKEND_SMTP_SENDER_NAME` - Sender display name
- `BACKEND_SMTP_USERNAME` - SMTP authentication username
- `BACKEND_SMTP_PASSWORD` - SMTP authentication password

## CLI Commands

```bash
uv run backend-actions --help
```

## Auth Server (Go)

The auth server is in the `/auth` directory.

### Building

CGO must be enabled (required for SQLite):

```bash
cd auth
CGO_ENABLED=1 go build .
```

### Running

```bash
./auth --env-file .env.test
```

Available flags:

- `--env-file` - Path to environment file (default: `.env`)
- `--user-server-port` - Port where the user server listens (default: 12790)
- `--command-port` - Port for management commands on 127.0.0.2 (default: 12771)
