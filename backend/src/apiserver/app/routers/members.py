from typing import List

from fastapi import APIRouter, Depends
from loguru import logger
from pydantic import TypeAdapter
from apiserver.app.dependencies import require_member

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


# @members_router.get("/profile/")
# async def get_profile(dsrc: SourceDep, member: RequireMember) -> UserData:
#     async with data.get_conn(dsrc) as conn:
#         user_data = await get_userdata_by_id(conn, member.sub)
#     logger.debug(f"{member.sub} requested profile")

#     return user_data


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
