from typing import AsyncIterator
from contextlib import asynccontextmanager
from fastapi import FastAPI
from apiserver.data import Db, model
from apiserver.settings import Settings
from apiserver.app_def import State

def inmemory_lifespan():
    @asynccontextmanager
    async def mock_lifespan(app: FastAPI) -> AsyncIterator[State]:
        db = Db(None)
        model.metadata.create_all(db.engine, checkfirst=False)

        yield {"db": db}

    return mock_lifespan
