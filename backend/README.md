# Dodeka Backend

## Installation

Install dependencies using the lockfile (production):

```bash
uv sync --frozen --no-dev
```

For development (includes linting/type checking tools):

```bash
uv sync --frozen
```

## Running

For local development (starts both Python backend and Go auth server):

```bash
uv run dev
```

For demo or production:

```bash
uv run --frozen --no-dev demo
uv run --frozen --no-dev production
```

With a custom env file:

```bash
uv run --frozen --no-dev backend --env-file /path/to/.env
```

## Architecture

The backend runs two HTTP servers:

- **Public API** (port `BACKEND_PORT`, default 12780) - Serves the frontend, handles user requests.
- **Private server** (port `BACKEND_PRIVATE_PORT`, default 12790, on 127.0.0.2) - Accepts commands from the Go auth server and CLI tools.

The Go auth server (tiauth-faroe) runs alongside:

- **Auth server** (port `FAROE_PORT`, default 12770) - Handles authentication (signup, login, sessions).
- **Auth command server** (port `FAROE_COMMAND_PORT`, default 12771, on 127.0.0.2) - Management commands (reset).

Port scheme by environment: test = 127xx, demo = 128xx, production = 129xx.

## Configuration

Settings are loaded from `.env` files in `envs/<environment>/`.

| Variable | Default | Description |
|---|---|---|
| `BACKEND_DB_FILE` | `./db.sqlite` | Path to SQLite database |
| `BACKEND_ENVIRONMENT` | `production` | Environment: `test`, `demo`, `production` |
| `BACKEND_AUTH_SERVER_URL` | `http://localhost:12770` | Go auth server URL |
| `BACKEND_AUTH_COMMAND_URL` | `http://127.0.0.2:12771` | Auth command server URL (used by `aa`) |
| `BACKEND_FRONTEND_ORIGIN` | `https://dsavdodeka.nl` | Frontend origin for CORS and CSRF |
| `BACKEND_DEBUG_LOGS` | `false` | Enable debug logging |
| `BACKEND_PORT` | `12780` | Public API port |
| `BACKEND_PRIVATE_PORT` | `12790` | Private server port (on 127.0.0.2) |

SMTP settings (optional, for sending emails):

| Variable | Description |
|---|---|
| `BACKEND_SMTP_HOST` | SMTP server hostname |
| `BACKEND_SMTP_PORT` | SMTP server port |
| `BACKEND_SMTP_SENDER_EMAIL` | Sender email address |
| `BACKEND_SMTP_SENDER_NAME` | Sender display name |
| `BACKEND_SMTP_USERNAME` | SMTP authentication username |
| `BACKEND_SMTP_PASSWORD` | SMTP authentication password |
| `BACKEND_SMTP_SEND` | `true` to send via SMTP, `false` to save to files |

## CLI Commands

Three CLI tools, each with a short alias:

### `da` / `dev-actions` - Dev Process Management

Controls the dev orchestrator (started by `uv run dev`).

| Command | Description |
|---|---|
| `da restart` | Send SIGHUP to reload code from disk |
| `da stop` | Gracefully stop the dev process |
| `da status` | Check if the dev process is running |

### `ba` / `backend-actions` - Backend Management

Sends commands to the backend private server. Requires the backend to be running.

**Database & system:**

| Command | Description |
|---|---|
| `ba reset` | Clear all tables and re-bootstrap admin |
| `ba get-admin-credentials` | Show bootstrap admin email/password |
| `ba board-setup` | One-time board (Bestuur) account setup |
| `ba board-renew` | Yearly board password reset + admin renewal |
| `ba grant-admin <email>` | Grant admin permission to a user |

**User management (testing):**

| Command | Description |
|---|---|
| `ba prepare-user <email> [-f name] [-l name]` | Create accepted newuser (test helper) |
| `ba create-accounts <password>` | Complete signup for all accepted newusers |
| `ba get-token <action> <email>` | Retrieve email verification code |

**Member sync (Atletiekunie CSV import):**

| Command | Description |
|---|---|
| `ba import-sync <csv_path>` | Import CSV member export into sync table |
| `ba sync-status` | Show sync groups (departed/new/pending/existing) |
| `ba accept-new [--email addr]` | Accept new sync users and send emails |
| `ba remove-departed [--email addr]` | Revoke member permission for departed users |
| `ba update-existing [--email addr]` | Update user data from sync |

### `aa` / `auth-actions` - Auth Server Management

Sends commands to the Go auth server's command port.

| Command | Description |
|---|---|
| `aa reset` | Clear all auth server data |

## Auth Server (Go)

The auth server binary is in `/auth`. If you use `uv run dev` you do not have to worry about building it, it will be downloaded from a recent GitHub CI run.

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

## Code structure
