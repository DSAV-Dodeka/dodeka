import logging
from contextlib import asynccontextmanager
from logging import Logger
from pathlib import Path
from typing import TypedDict

from uvicorn.logging import DefaultFormatter

from fastapi import FastAPI, Request
from fastapi.middleware import Middleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.routing import Mount
from fastapi.exceptions import RequestValidationError
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.types import ASGIApp

# We rely upon database parameters being set at import time, which is fragile, but the only way to easily re-use it
# in the app state
# In most cases this is where all environment variables and other configuration is loaded

from apiserver.define import (
    res_path,
    ErrorResponse,
    error_response_handler,
    LOGGER_NAME,
    allowed_envs,
    error_response_return,
)
from apiserver.env import load_config, Config

import apiserver.utilities as util

# Import types separately to make it clear in what line the module is first loaded and its top-level run
from apiserver.data import Source

# Router modules, each router has its own API endpoints
import apiserver.routers.basic as basic
import apiserver.routers.auth as auth
import apiserver.routers.profile as profile
import apiserver.routers.onboard as onboard
import apiserver.routers.update as update
import apiserver.routers.admin as admin
import apiserver.routers.users as users


class LoggerMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, mw_logger: Logger):
        super().__init__(app)
        self.mw_logger = mw_logger

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint):
        # self.mw_logger.debug(request.headers)
        return await call_next(request)


def init_logging(logger_name: str, log_level: int):
    logger_init = logging.getLogger(logger_name)
    logger_init.setLevel(log_level)
    str_handler = logging.StreamHandler()
    # handler = logging.FileHandler(filename=log_path)
    log_format = "%(levelprefix)s %(asctime)s | %(message)s "
    formatter = DefaultFormatter(log_format, datefmt="%Y-%m-%d %H:%M:%S")
    # handler.setFormatter(formatter)
    str_handler.setFormatter(formatter)
    # logger_init.addHandler(handler)
    logger_init.addHandler(str_handler)
    return logger_init


class State(TypedDict):
    dsrc: Source
    config: Config


@asynccontextmanager
async def lifespan(app: FastAPI) -> State:
    logger.info("Running startup...")
    dsrc = Source()
    config = await app_startup(dsrc)
    yield {"config": config, "dsrc": dsrc}
    logger.info("Running shutdown...")
    await app_shutdown(dsrc)


def create_app(app_lifespan) -> tuple[FastAPI, Logger]:
    new_logger = init_logging(LOGGER_NAME, logging.DEBUG)

    # TODO change all origins
    origins = [
        "*",
    ]
    routes = [
        Mount(
            "/credentials",
            app=StaticFiles(
                directory=res_path.joinpath("static/credentials"), html=True
            ),
            name="credentials",
        )
    ]
    middleware = [
        Middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_methods=["*"],
            allow_headers=["Authorization"],
        ),
        Middleware(LoggerMiddleware, mw_logger=new_logger),
    ]

    new_app = FastAPI(
        title="apiserver", routes=routes, middleware=middleware, lifespan=app_lifespan
    )
    new_app.include_router(basic.router)
    new_app.include_router(auth.router)
    new_app.include_router(profile.router)
    new_app.include_router(onboard.router)
    new_app.include_router(update.router)
    new_app.include_router(admin.router)
    new_app.include_router(users.router)
    new_app.add_exception_handler(ErrorResponse, handler=error_response_handler)
    # TODO change logger behavior in tests

    new_logger.info("Starting...")

    return new_app, new_logger


# Running FastAPI relies on the fact the app is created at module top-level
# Seperating the logic in a function also allows it to be called elsewhere, like tests
apiserver_app, logger = create_app(lifespan)


# Should always be manually run in tests
def safe_startup(dsrc_inst: Source, config: Config):
    dsrc_inst.init_gateway(config)


# We use the functions below, so we can also manually call them in tests


async def app_startup(dsrc_inst: Source):
    # Only startup events that do not work in all environments or require other processes to run belong here
    # Safe startup events with variables that depend on the environment, but should always be run, can be included in
    # the 'safe_startup()' above
    # Safe startup events that do not depend on the environment, can be included in the 'create_app()' above
    config = load_config()
    if config.APISERVER_ENV not in allowed_envs:
        raise RuntimeError(
            "Runtime environment (env.toml) does not correspond to compiled environment"
            " (define.toml)! Ensure defined variables are appropriate for the runtime"
            " environment before changing the environment!"
        )
    if config.APISERVER_ENV == "localdev":
        cr_time = util.when_modified(res_path.joinpath("static/credentials"))
        src_time = util.when_modified(
            res_path.parent.parent.parent.joinpath("authpage/src")
        )
        if cr_time > src_time:
            logger.warning(
                "Most likely authpage has not been recently built for development,"
                " please run `npm run build` in /authpage directory."
            )

    safe_startup(dsrc_inst, config)
    # Db connections, etc.
    do_recreate = config.RECREATE == "yes"
    await dsrc_inst.startup(config, do_recreate)

    return config


async def app_shutdown(dsrc_inst: Source):
    await dsrc_inst.shutdown()


@apiserver_app.exception_handler(RequestValidationError)
def validation_exception_handler(request, exc: RequestValidationError):
    # Also show debug if there is an error in the request
    exc_str = str(exc)
    logger.debug(str(exc))
    return error_response_return(
        err_status_code=400, err_type="bad_request_validation", err_desc=exc_str
    )
