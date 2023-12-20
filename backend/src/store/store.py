from typing import AsyncContextManager, Optional, TypeAlias

from redis import ConnectionError as RedisConnectionError
from pydantic import BaseModel
from redis.asyncio import Redis
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine, AsyncConnection

from store.error import StoreObjectError


class StoreConfig(BaseModel):
    DB_USER: str
    DB_PASS: str
    DB_HOST: str
    DB_PORT: int
    DB_NAME: str

    KV_HOST: str
    KV_PORT: int
    # RECOMMENDED TO LOAD AS ENVIRON
    KV_PASS: str


class Store:
    db: Optional[AsyncEngine] = None
    kv: Optional[Redis] = None
    db_url: Optional[str]
    # Session is for reusing a single connection across multiple functions
    session: Optional[AsyncConnection] = None

    def init_objects(self, config: StoreConfig) -> None:
        """Connections are not actually established, it simply initializes the connection parameters."""
        db_cluster = (
            f"{config.DB_USER}:{config.DB_PASS}@{config.DB_HOST}:{config.DB_PORT}"
        )
        self.db_url = f"{db_cluster}/{config.DB_NAME}"
        # #
        self.kv = Redis(
            host=config.KV_HOST, port=config.KV_PORT, db=0, password=config.KV_PASS
        )

        self.db = create_async_engine(f"postgresql+asyncpg://{self.db_url}")

    def recreate_engine(self) -> None:
        self.db = create_async_engine(f"postgresql+asyncpg://{self.db_url}")

    async def ping(self) -> None:
        """Connects with external data sources to see if they are online.

        Raises:
            StoreError: If external datasources or not running or if Store is not initialized.
        """
        if self.kv is None or self.db is None:
            raise StoreObjectError(
                f"Cannot ping: KV: {self.kv!s} or DB: {self.db!s} not initialized!"
            )

        try:
            await self.kv.ping()
        except RedisConnectionError:
            raise StoreObjectError(
                "Unable to ping Redis server! Please check if it is running."
            )
        try:
            async with self.db.connect() as conn:
                _ = conn.info
        except SQLAlchemyError:
            raise StoreObjectError(
                "Unable to connect to DB with SQLAlchemy! Please check if it is"
                " running."
            )

    async def disconnect(self) -> None:
        if self.kv is None or self.db is None:
            raise StoreObjectError(
                f"Cannot disconnect: KV: {self.kv!s} or DB: {self.db!s} not"
                " initialized!"
            )
        await self.kv.close()
        await self.db.dispose()

    async def startup(self) -> None:
        """Runs `self.ping()`, to check if it can connect to the external data sources.

        Raises:
            StoreError: If external datasources or not running or if Store is not initialized.
        """
        await self.ping()

    async def shutdown(self) -> None:
        await self.disconnect()


StoreContext: TypeAlias = AsyncContextManager[Store]


class FakeStore(Store):
    pass
