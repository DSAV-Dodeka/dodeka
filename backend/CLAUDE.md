# Claude Development Guidelines

## Project Layout

- Backend: `~/files/dodekap/dodeka/backend/`
- Frontend: `~/files/dodekap/dodekafrontend/`

## Architecture

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
