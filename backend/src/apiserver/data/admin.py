from loguru import logger

from sqlalchemy import text
from sqlalchemy.engine import Engine


def drop_recreate_database(engine: Engine, db_name: str) -> None:
    raise Exception("not yet implemented recreate!")
    # with engine.connect() as connection:
    # terminate_conns = text(f"""
    #                        SELECT pg_terminate_backend(pg_stat_activity.pid)
    #                         FROM pg_stat_activity
    #                         WHERE pg_stat_activity.datname = '{db_name}'
    #                         AND pid <> pg_backend_pid();""")
    # connection.execute(terminate_conns)

    # drop_db = text(f"DROP DATABASE IF EXISTS {db_name}")
    # connection.execute(drop_db)
    # create_db = text(f"CREATE DATABASE {db_name}")
    # connection.execute(create_db)
    # logger.warning("Dropped and recreated database.")
