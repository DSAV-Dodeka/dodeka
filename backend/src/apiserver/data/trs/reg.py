from store.kv import store_json, get_json, pop_json, store_string, get_string
from apiserver.data import Source, get_kv
from store.error import NoDataError
from apiserver.lib.model.entities import UpdateEmailState, Signup
from auth.core.model import SavedRegisterState


async def get_register_state(dsrc: Source, auth_id: str) -> SavedRegisterState:
    state_dict = await get_json(get_kv(dsrc), auth_id)
    if state_dict is None:
        raise NoDataError("State does not exist or expired.", "saved_state_empty")
    return SavedRegisterState.model_validate(state_dict)


async def store_email_confirmation(
    dsrc: Source, confirm_id: str, email: str, email_expiration: int
) -> None:
    await store_string(get_kv(dsrc), email, confirm_id, expire=email_expiration)


async def get_email_confirmation(dsrc: Source, email: str) -> str:
    """Returns the confirm id stored for the email."""
    stored_confirm_id = await get_string(get_kv(dsrc), email)
    if stored_confirm_id is None:
        raise NoDataError(
            "No current confirmation flow for email", "saved_confirm_empty"
        )
    return stored_confirm_id


async def store_update_email(
    dsrc: Source, flow_id: str, update_email: UpdateEmailState
) -> None:
    await store_json(get_kv(dsrc), flow_id, update_email.model_dump(), expire=1000)


async def get_update_email(dsrc: Source, user_id: str) -> UpdateEmailState:
    email_dict = await pop_json(get_kv(dsrc), user_id)
    if email_dict is None:
        raise NoDataError(
            "User ID has no active update request.", "saved_email_update_empty"
        )
    return UpdateEmailState.model_validate(email_dict)
