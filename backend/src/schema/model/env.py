from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context
from schema.model import metadata


# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# the following is necessary because we want to be able to call this from the deploy server
# we don't want any dependencies on apiserver or other things as a result in the schema package
try:
    raise ImportError
    # from apiserver.env import load_config
    # from apiserver.resources import project_path

    # api_config = load_config(project_path.joinpath("devenv.toml"))
    # db_cluster = f"postgresql+psycopg://{api_config.DB_USER}:{api_config.DB_PASS}@{api_config.DB_HOST}:{api_config.DB_PORT}"
    # db_url = f"{db_cluster}/{api_config.DB_NAME}"
except ImportError:
    import os

    # This should be the part after ://
    env_db_url = os.environ.get("DATABASE_URL")

    if env_db_url is None:
        raise ValueError(
            "DATABASE_URL environment variable must be defined to connect to database!"
        )
    db_url = f"postgresql+psycopg://{env_db_url}"


config.set_main_option("sqlalchemy.url", db_url)
if config.config_file_name is None:
    raise ValueError("config_file_name cannot be none!")

# Interpret the config file for Python logging.
# This line sets up loggers basically.
fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    cfg_section = config.get_section(config.config_ini_section)
    print(cfg_section)
    if cfg_section is None:
        raise ValueError(f"section {config.config_ini_section} must exist!")
    connectable = engine_from_config(
        cfg_section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
