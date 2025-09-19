# SQLite decisions

We don't let tables have a `rowid` (https://www.sqlite.org/rowidtable.html, SQLite designer says " In a perfect world, there would be no such thing as a "rowid" and all tables would following the standard semantics implemented as WITHOUT ROWID tables, only without the extra "WITHOUT ROWID" keywords".
- Therefore, we use `sqlite_with_rowid=False`.

SQLite can be somewhat lax with types, but there's no really no benefit for us. It only enables accidentally putting the wrong types in columns (https://www.sqlite.org/stricttables.html).
- Therefore, we use `sqlite_strict=True`.

We want to enable foreign keys, to make it more like other relational databases (https://docs.sqlalchemy.org/en/20/dialects/sqlite.html#foreign-key-support).
- Therefore, we listen for engine connect events to always enable foreign key support for new connections.

Since SQLite doesn't offer the same level of support for modifying tables, there exists  update support (https://alembic.sqlalchemy.org/en/latest/batch.html#batch-mode-with-autogenerate). This works only with online mode, so we also won't be using offline mode (so it is removed from env.py).
- Therefore, we raise an error when offline mode is selected in `env.py`.
-

SQLite can work with threads, but they actually rather you don't. Instead, you can just make multiple connections. Because of the GIL, Python will be thread-safe. Any parallelism will be achieved by using multiple workers. Now, since we try to avoid using async in FastAPI to keep everything simple, in practice everything will be run in a threadpool. Hence, there will be multiple threads and therefore we want to have multiple connections available. SQLAlchemy supports this by default by using the default QueuePool.
- Therefore, we use the default QueuePool. In alembic, there will be a single connection and we use the default NullPool.

## Running a migration

First, generate the migration with (replace `<NAME>` with an actual name).

```
uv run alembic revision --autogenerate -m "<NAME>"
```

Look at the generated migration to ensure everything makes sense.

Then, execute:

```
uv run alembic upgrade head
```
