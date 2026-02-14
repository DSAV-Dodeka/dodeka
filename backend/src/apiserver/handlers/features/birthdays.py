"""Birthday feature for members."""

import logging

from freetser import Response
from freetser.server import StorageQueue

from apiserver.data.features.birthdays import list_birthdays

logger = logging.getLogger("apiserver.handlers.features.birthdays")


def birthdays_handler(store_queue: StorageQueue) -> Response:
    """Handle /members/birthdays/ - list all member birthdays."""
    result = store_queue.execute(list_birthdays)
    logger.info(f"birthdays: Returning {len(result)} entries")
    return Response.json(result)
