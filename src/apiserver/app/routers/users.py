from fastapi import APIRouter, Request

from apiserver import data
from apiserver.lib.model.entities import BirthdayData
from apiserver.app.error import ErrorResponse
from apiserver.app.ops.header import Authorization
from apiserver.data import Source

from apiserver.app.routers.helper import require_member

router = APIRouter()


@router.get("/members/birthdays/", response_model=list[BirthdayData])
async def get_user_birthdays(request: Request, authorization: Authorization):
    dsrc: Source = request.state.dsrc
    await require_member(authorization, dsrc)

    async with data.get_conn(dsrc) as conn:
        birthday_data = await data.user.get_all_birthdays(conn)
    return birthday_data


@router.get("/members/rankings/{rank_type}")
async def get_user_rankings(rank_type, request: Request, authorization: Authorization):
    dsrc: Source = request.state.dsrc
    await require_member(authorization, dsrc)

    if rank_type != "training" and rank_type != "points" and rank_type != "pr":
        reason = f"Ranking {rank_type} is unknown!"
        raise ErrorResponse(
            status_code=400,
            err_type="invalid_ranking",
            err_desc=reason,
            debug_key="bad_ranking",
        )

    ranking_data = await data.file.load_json(rank_type)
    return ranking_data
