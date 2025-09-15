from typing import Type
from pathlib import Path
from sqlalchemy import Engine, create_engine, event, Pool
from sqlalchemy.pool.impl import QueuePool


class Db:
    engine: Engine

    def __init__(self, db_file: Path | None):
        self.engine = init_sqlite_engine(db_file)



def init_sqlite_engine(db_file: Path | None, poolclass: Type[Pool]|None = QueuePool) -> Engine:
    # To see why we do autocommit: False, see docs.sqlalchemy.org/en/20/dialects/sqlite.html#enabling-non-legacy-sqlite-transactional-modes-with-the-sqlite3-or-aiosqlite-driver
    # We use the default QueuePool, because we try to avoid async and hence FastAPI runs us in a
    # threadpool, which means we do use multiple threads in which case using a pool of connections
    if db_file is None:
        file_str = ":memory:"
    else:
        file_str = str(db_file)
    engine = create_engine(
        f"sqlite+pysqlite:///{file_str}", connect_args={"autocommit": False}, poolclass=poolclass
    )

    # https://docs.sqlalchemy.org/en/20/dialects/sqlite.html#foreign-key-support
    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        # the sqlite3 driver will not set PRAGMA foreign_keys
        # if autocommit=False; set to True temporarily
        ac = dbapi_connection.autocommit
        dbapi_connection.autocommit = True

        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

        # restore previous autocommit setting
        dbapi_connection.autocommit = ac

    return engine
