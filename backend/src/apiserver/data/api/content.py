from typing import Any, Optional, cast
from sqlalchemy.ext.asyncio import AsyncConnection
from store.db import select_some_two_where
from schema.model import CONTENT_TABLE, CONTENT_DATA, CONTENT_CATEGORY, CONTENT_ID


async def get_content_data(
    conn: AsyncConnection, category: str, content_id: str
) -> Optional[dict[str, Any]]:
    content_list = await select_some_two_where(
        conn,
        CONTENT_TABLE,
        {CONTENT_DATA},
        CONTENT_CATEGORY,
        category,
        CONTENT_ID,
        content_id,
    )
    if len(content_list) == 0:
        return None
    return cast(dict[str, Any], content_list[0][CONTENT_DATA])
