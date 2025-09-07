# from datetime import date
# from apiserver.data.api.trainings import add_training_event
# from datacontext.context import ContextRegistry
# from typing import Any, Literal
# from schema.model.model import CLASS_EVENTS_TABLE
# from store.db import retrieve_by_unique

# from store.error import DataError

# from apiserver.lib.model.entities import (
#     ClassEvent,
#     ClassMeta,
#     ClassUpdate,
#     ClassView,
#     NewEvent,
#     NewTrainingEvent,
#     RankingInfo,
#     UserEvent,
#     UserPointsNames,
# )
# from apiserver.data import Source
# from apiserver.data.api.classifications import (
#     add_class_event,
#     add_users_to_event,
#     all_points_in_class,
#     class_last_updated,
#     class_update_last_updated,
#     events_in_class,
#     get_event_user_points,
#     insert_classification,
#     most_recent_class_of_type,
#     update_classification,
# )
# from apiserver.data.context import RankingContext
# from apiserver.data.source import get_conn
# from apiserver.data.special import update_class_points, user_events_in_class
# from apiserver.app.error import ErrorKeys, AppError


# ctx_reg = ContextRegistry()


# def check_add_to_class(classification: ClassView, new_event: NewEvent) -> None:
#     """Checks whether the event is after the classification start date. Throws AppError if not correct."""
#     if classification.start_date > new_event.date:
#         desc = "Event cannot happen before start of classification!"
#         raise AppError(ErrorKeys.RANKING_UPDATE, desc, "ranking_date_before_start")


# @ctx_reg.register(RankingContext)
# async def add_new_event(dsrc: Source, new_event: NewEvent) -> None:
#     """Add a new event and recompute points. Display points will be updated to not include any events after the hidden
#     date. Use the 'publish' function to force them to be equal."""
#     async with get_conn(dsrc) as conn:
#         try:
#             classification = (
#                 await most_recent_class_of_type(conn, new_event.class_type)
#             )[0]
#         except DataError as e:
#             if e.key != "incorrect_class_type":
#                 raise e
#             raise AppError(ErrorKeys.RANKING_UPDATE, e.message, "incorrect_class_type")

#         # THROWS AppError
#         check_add_to_class(classification, new_event)

#         event_id = await add_class_event(
#             conn,
#             new_event.event_id,
#             classification.classification_id,
#             new_event.category,
#             new_event.date,
#             new_event.description,
#         )

#         try:
#             await add_users_to_event(conn, event_id=event_id, points=new_event.users)
#         except DataError as e:
#             if e.key != "database_integrity":
#                 raise e
#             raise AppError(
#                 ErrorKeys.RANKING_UPDATE,
#                 e.message,
#                 "add_event_users_violates_integrity",
#             )

#         await update_class_points(
#             conn,
#             classification.classification_id,
#         )

#     # we want in a new transaction to ensure the event has been added
#     async with get_conn(dsrc) as conn:
#         # this can throw but should never happen after above transaction
#         last_updated_date = await class_last_updated(
#             conn, classification.classification_id
#         )
#         await class_update_last_updated(
#             conn, classification.classification_id, last_updated_date
#         )


# async def add_new_training(dsrc: Source, new_event: NewTrainingEvent) -> None:
#     async with get_conn(dsrc) as conn:
#         event_ids = await add_training_event(
#             conn,
#             1,
#             list(new_event.categoriesEnrolled.keys()),
#             new_event.date,
#             new_event.description,
#         )

#         try:
#             for event_id in event_ids:
#                 event: dict[str, Any] | None = await retrieve_by_unique(
#                     conn, CLASS_EVENTS_TABLE, "event_id", event_id
#                 )
#                 if event is None:
#                     raise DataError("event_not_found", "Event not found")

#                 users = new_event.categoriesEnrolled[event["category"]]
#                 print(users)
#                 await add_users_to_event(conn, event_id=event_id, points=users)
#         except DataError as e:
#             if e.key != "database_integrity":
#                 raise e
#             raise AppError(
#                 ErrorKeys.RANKING_UPDATE,
#                 e.message,
#                 "add_event_users_violates_integrity",
#             )

#         await update_class_points(
#             conn,
#             1,
#         )


# @ctx_reg.register(RankingContext)
# async def context_most_recent_class_id_of_type(
#     dsrc: Source, rank_type: Literal["points", "training"]
# ) -> int:
#     async with get_conn(dsrc) as conn:
#         class_id = (await most_recent_class_of_type(conn, rank_type))[
#             0
#         ].classification_id

#     return class_id


# @ctx_reg.register(RankingContext)
# async def context_most_recent_class_points(
#     dsrc: Source,
#     rank_type: Literal["points", "training"],
#     is_admin: bool,
# ) -> RankingInfo:
#     async with get_conn(dsrc) as conn:
#         class_view = (await most_recent_class_of_type(conn, rank_type))[0]
#         user_points = await all_points_in_class(
#             conn, class_view.classification_id, is_admin
#         )

#     is_frozen = date.today() >= class_view.hidden_date
#     ranking_info = RankingInfo(
#         points=user_points, last_updated=class_view.last_updated, frozen=is_frozen
#     )

#     return ranking_info


# @ctx_reg.register(RankingContext)
# async def sync_publish_ranking(dsrc: Source, publish: bool) -> None:
#     async with get_conn(dsrc) as conn:
#         training_class = (await most_recent_class_of_type(conn, "training"))[0]
#         points_class = (await most_recent_class_of_type(conn, "points"))[0]
#         await update_class_points(conn, training_class.classification_id, publish)
#         await update_class_points(conn, points_class.classification_id, publish)


# @ctx_reg.register(RankingContext)
# async def context_user_events_in_class(
#     dsrc: Source, user_id: str, class_id: int
# ) -> list[UserEvent]:
#     async with get_conn(dsrc) as conn:
#         user_events = await user_events_in_class(conn, user_id, class_id)

#     return user_events


# @ctx_reg.register(RankingContext)
# async def context_events_in_class(dsrc: Source, class_id: int) -> list[ClassEvent]:
#     async with get_conn(dsrc) as conn:
#         events = await events_in_class(conn, class_id)

#     return events


# @ctx_reg.register(RankingContext)
# async def context_get_event_users(dsrc: Source, event_id: str) -> list[UserPointsNames]:
#     """If resulting list is empty, either the event doesn't exist or it has no users in it."""
#     async with get_conn(dsrc) as conn:
#         events_points = await get_event_user_points(conn, event_id)

#     return events_points


# MIN_AMOUNT = 2


# @ctx_reg.register(RankingContext)
# async def most_recent_classes(dsrc: Source, amount: int = 10) -> list[ClassMeta]:
#     if amount < MIN_AMOUNT or amount % 2 != 0:
#         raise AppError(
#             ErrorKeys.DATA,
#             "Request at least 2 classes and make sure it is an even number!",
#             "most_recent_too_few",
#         )

#     async with get_conn(dsrc) as conn:
#         training_classes = await most_recent_class_of_type(
#             conn, "training", amount // 2
#         )
#         points_classes = await most_recent_class_of_type(conn, "points", amount // 2)

#     return training_classes + points_classes


# @ctx_reg.register(RankingContext)
# async def context_new_classes(dsrc: Source) -> None:
#     async with get_conn(dsrc) as conn:
#         new_training_id = await insert_classification(conn, "training")
#         new_points_id = await insert_classification(conn, "points")

#         await update_class_points(conn, new_training_id, False)
#         await update_class_points(conn, new_points_id, False)


# @ctx_reg.register(RankingContext)
# async def context_modify_class(dsrc: Source, class_update: ClassUpdate) -> None:
#     async with get_conn(dsrc) as conn:
#         await update_classification(conn, class_update)
#         await update_class_points(conn, class_update.classification_id, False)
