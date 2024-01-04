from apiserver.app.dependencies import require_member
from apiserver.app.response import RawJSONResponse
from fastapi import APIRouter, Depends

dev = True

personal_record_router = APIRouter(
    prefix="/personalrecord", tags=["personalrecord"], dependencies=[Depends(require_member)] if not dev else []
)

@personal_record_router.get("/")
async def read_root() -> dict[str, str]:
    return {"PR": "Die heb jij niet loser, womp womp"}

@personal_record_router.get("/get/{onderdeel}", response_model=dict[str, str])
async def get_onderdeel(onderdeel: str) -> RawJSONResponse:
    return {"Onderdeel": onderdeel}