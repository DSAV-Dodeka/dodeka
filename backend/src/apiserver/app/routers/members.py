from typing import List

from fastapi import APIRouter, Depends
from loguru import logger
from pydantic import TypeAdapter, BaseModel
from apiserver.data.members import get_member, MemberData
from apiserver.app.dependencies import require_member, Member, DbDep, RequireMember

# from apiserver.app.error import ErrorResponse
# from apiserver.data.api.content import get_content_data
# import apiserver.data.api.ud.birthday
# from apiserver import data
# from apiserver.app.response import RawJSONResponse
# from apiserver.data.api.ud.userdata import get_userdata_by_id
# from apiserver.lib.model.entities import BirthdayData, UserData
# import orjson

members_router = APIRouter(
    prefix="/members", tags=["members"], dependencies=[Depends(require_member)]
)

# BirthdayList = TypeAdapter(List[BirthdayData])


# @members_router.get("/birthdays/", response_model=list[BirthdayData])
# async def get_user_birthdays(dsrc: SourceDep, member: RequireMember) -> RawJSONResponse:
#     async with data.get_conn(dsrc) as conn:
#         birthday_data = await apiserver.data.api.ud.birthday.get_all_birthdays(conn)
#     logger.debug(f"{member.sub} requested birthdays")

#     return RawJSONResponse(BirthdayList.dump_json(birthday_data))



@members_router.get("/profile/")
def get_profile(db: DbDep, member: RequireMember) -> MemberData:
    return get_member(db, member.user_id)

# @members_router.get("/content/{category}/{content_id}")
# async def get_content(
#     dsrc: SourceDep, member: RequireMember, category: str, content_id: str
# ) -> RawJSONResponse:
#     async with data.get_conn(dsrc) as conn:
#         maybe_content = await get_content_data(conn, category, content_id)

#     if maybe_content is None:
#         raise ErrorResponse(
#             404, "content_not_found", f"Could not find content {category}/{content_id}"
#         )

#     logger.debug(f"{member.sub} requested content {category}/{content_id}")

#     return RawJSONResponse(orjson.dumps({"content": maybe_content}))
