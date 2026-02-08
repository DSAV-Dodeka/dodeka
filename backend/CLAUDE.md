# Claude Development Guidelines

## Project Layout

- Backend: `~/files/dodekap/dodeka/backend/`
- Frontend: `~/files/dodekap/dodekafrontend/`

## Architecture

Two HTTP servers run in the Python backend process:

- **Public API** (`BACKEND_PORT`, default 12780) on 0.0.0.0 - Frontend-facing routes with CORS and CSRF protection.
- **Private server** (`BACKEND_PRIVATE_PORT`, default 12790) on 127.0.0.2 - Accepts `/command`, `/invoke`, `/email` from the Go auth server and CLI tools.

The Go auth server (tiauth-faroe) runs as a separate process:

- **Auth server** (`FAROE_PORT`, default 12770) on 0.0.0.0 - Authentication (signup, login, sessions).
- **Command server** (`FAROE_COMMAND_PORT`, default 12771) on 127.0.0.2 - Management commands.

Port scheme: test = 127xx, demo = 128xx, production = 129xx.

### CLI Tools

- `da` (`dev-actions`) - Dev process control: `restart`, `stop`, `status`. Sends signals to the dev orchestrator PID.
- `ba` (`backend-actions`) - Backend management: sends HTTP commands to the private server (127.0.0.2). Commands: `reset`, `prepare-user`, `get-admin-credentials`, `get-token`, `board-setup`, `board-renew`, `grant-admin`, `create-accounts`, `import-sync`, `sync-status`, `accept-new`, `remove-departed`, `update-existing`.
- `aa` (`auth-actions`) - Auth server management: sends HTTP commands to the auth command server (127.0.0.2). Commands: `reset`.

### Key Files

- `app.py` - Main server, route handlers, CSRF protection, permission checks
- `private.py` - Private server handlers, command dispatch
- `commands.py` - CLI command implementations (HTTP client to private server)
- `dev.py` - Dev orchestrator (manages both Go and Python processes)
- `settings.py` - Configuration loading from .env files
- `sync.py` - Member sync (CSV import, group computation)
- `data/` - Database operations (users, permissions, registration state, etc.)

## Code Quality Checks

After adding a significant amount of code and before finishing a request, run these checks:

```bash
uv run ty check          # Type checking
uv run ruff format       # Code formatting (just run it, accept all changes)
uv run ruff check        # Linting
```

All checks must pass. Try to avoid ignoring warnings without explicit permission from the user.

## Naming Conventions

Never use leading underscores for function names, method names, class names, or variables. No `_my_function`, no `_InteractiveParser`, no `self._field`. Just use plain names without underscores prefix.

## Error Signalling

Never use `None` to signal errors or failure states from functions. Instead, use explicit sentinel dataclasses (e.g. `InvalidHeaders`, `UserNotFound`, `EmailNotFoundInNewUserTable`) and check with `isinstance()`. This makes error paths visible in type signatures and avoids ambiguity with legitimate `None` values.

## Database Thread Deadlock Prevention

Never make blocking calls (HTTP, file I/O, etc.) inside database procedures passed to `store_queue.execute()`. The single-threaded database queue can deadlock if a procedure blocks waiting for a response that needs database access.

**Wrong:**
```python
def handler(req: Request, store_queue: StorageQueue) -> Response:
    def db_procedure(store: Storage):
        result = auth_client.get_session(token)  # Blocks DB thread
        # ... use result
    return store_queue.execute(db_procedure)
```

**Correct:**
```python
def handler(req: Request, store_queue: StorageQueue) -> Response:
    result = auth_client.get_session(token)  # Do blocking call first

    def db_procedure(store: Storage):
        # Only database operations, no blocking calls
        # ... use result
    return store_queue.execute(db_procedure)
```

See `session_info()` in `src/apiserver/app.py` for an example.

## Frontend
