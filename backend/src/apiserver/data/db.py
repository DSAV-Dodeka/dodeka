

from pathlib import Path
from sqlalchemy import Engine, create_engine


class Db:
    engine: Engine

    def __init__(self, db_file: Path):
        self.engine = init_engine(db_file)


def init_engine(db_file: Path) -> Engine:
    # To see why we do autocommit: False, see docs.sqlalchemy.org/en/20/dialects/sqlite.html#enabling-non-legacy-sqlite-transactional-modes-with-the-sqlite3-or-aiosqlite-driver
    # We use the default QueuePool, because we try to avoid async and hence FastAPI runs us in a
    # threadpool, which means we do use multiple threads in which case using a pool of connections
    # is also better
    engine = create_engine(
        f"sqlite:///{str(db_file)}", connect_args={"autocommit": False}
    )

    return engine