from fastapi import APIRouter, Depends

from apiserver.app.dependencies import RequireMember, SourceDep, require_member
from apiserver.app.response import RawJSONResponse
from apiserver.lib.model.entities import PRRecordData
from apiserver import data
from loguru import logger
import apiserver.data.api.ud.personalrecord as pr

dev = True

personal_record_router = APIRouter(
    prefix="/personalrecord", tags=["personalrecord"], dependencies=[Depends(require_member)] if not dev else []
)

@personal_record_router.get("/")
async def read_root() -> dict[str, str]:
    return {"PR": "Die heb jij niet loser, womp womp"}

@personal_record_router.get("/get/", response_model=list[PRRecordData])
async def get_all_prs(dsrc: SourceDep) -> RawJSONResponse:
    async with data.get_conn(dsrc) as conn:
        pr_data = await pr.get_all_prs(conn)
    #logger.debug(f"{member.sub} requested prs")

    return RawJSONResponse(pr.PRList.dump_json(pr_data))