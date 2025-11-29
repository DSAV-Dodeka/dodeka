import json
from dataclasses import dataclass

from hfree import Storage


@dataclass
class MemberData:
    user_id: str
    email: str
    firstname: str
    lastname: str


def get_member(store: Storage, user_id: str) -> MemberData:
    """Get member information for a given user_id."""
    # Read user data from separate keys
    profile_result = store.get("users", f"{user_id}:profile")
    email_result = store.get("users", f"{user_id}:email")

    if profile_result is None or email_result is None:
        raise ValueError("User not found")

    # Parse profile
    profile_bytes, _ = profile_result
    profile_data = json.loads(profile_bytes.decode("utf-8"))

    # Parse email
    email_bytes, _ = email_result
    email = email_bytes.decode("utf-8")

    return MemberData(
        user_id=user_id,
        email=email,
        firstname=profile_data["firstname"],
        lastname=profile_data["lastname"],
    )
