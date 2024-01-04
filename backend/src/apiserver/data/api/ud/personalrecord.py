from typing import List

from pydantic import TypeAdapter
from sqlalchemy import RowMapping
from sqlalchemy.ext.asyncio import AsyncConnection

from apiserver.lib.model.entities import PRRecordData
from schema.model import (
    PR_RECORDS_TABLE,
    PR_NAME,
    PR_EVENT,
    PR_PRESTATION,
    PR_DATE,
    PR_PLACE,
    PR_LINK,
    PR_VALID
)

from store.db import select_some_where
from store.error import NoDataError

PRList = TypeAdapter(List[PRRecordData])

def parse_pr_data(prs: list[RowMapping]) -> list[PRRecordData]:
    if len(prs) == 0:
        raise NoDataError("PRData does not exist.", "pr_data_empty")
    return PRList.validate_python(prs)


async def get_all_prs(conn: AsyncConnection) -> list[PRRecordData]:
    all_prs = await select_some_where(
        conn,
        PR_RECORDS_TABLE,
        {PR_NAME, PR_EVENT, PR_PRESTATION, PR_DATE, PR_PLACE, PR_LINK, PR_VALID},
        PR_VALID,
        "1"
    )
    return parse_pr_data(all_prs)