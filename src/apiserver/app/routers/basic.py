import logging

from fastapi import APIRouter

from apiserver.define import LOGGER_NAME

router = APIRouter()

logger = logging.getLogger(LOGGER_NAME)


@router.get("/")
async def read_root() -> dict[str, str]:
    return {"Hallo": "Atleten"}
