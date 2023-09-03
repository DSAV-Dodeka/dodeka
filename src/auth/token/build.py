import secrets
from secrets import token_urlsafe
from typing import Type

from auth.token.build_util import encode_token_dict, decode_refresh
from auth.hazmat.sign_token import finish_encode_token
from auth.core.model import RefreshToken, IdInfo, IdToken, SavedAccessToken
from auth.hazmat.structs import PEMPrivateKey, SymmetricKey
from auth.data.schemad.entities import SavedRefreshToken
from auth.token.crypt import encrypt_refresh


def build_refresh_save(
    saved_refresh: SavedRefreshToken, id_info_model: Type[IdInfo], utc_now: int
):
    # Rebuild access and ID tokens from value in refresh token
    # We need the core static info to rebuild with new iat, etc.
    saved_access, saved_id_token, id_info = decode_refresh(saved_refresh, id_info_model)
    user_id = saved_id_token.sub

    # Scope to be returned in response
    access_scope = saved_access.scope

    # Nonce is used to make it impossible to 'guess' new refresh tokens
    # (So it becomes a combination of family_id + id nr + nonce)
    # Although signing and encrypting should also protect it from that
    new_nonce = token_urlsafe(16).rstrip("=")
    # We don't store the access tokens and refresh tokens in the final token
    # To construct new tokens, we need that information so we save it in the DB
    new_refresh_save = SavedRefreshToken(
        family_id=saved_refresh.family_id,
        access_value=saved_refresh.access_value,
        id_token_value=saved_refresh.id_token_value,
        exp=saved_refresh.exp,
        iat=utc_now,
        nonce=new_nonce,
        user_id=saved_refresh.user_id,
    )

    return (
        saved_access,
        saved_id_token,
        id_info,
        user_id,
        access_scope,
        new_nonce,
        new_refresh_save,
    )


def build_refresh_token(
    new_refresh_id: int,
    saved_refresh: SavedRefreshToken,
    new_nonce: str,
    refresh_key: SymmetricKey,
):
    # The actual refresh token is an encrypted JSON dictionary containing the id,
    # family_id and nonce
    refresh = RefreshToken(
        id=new_refresh_id, family_id=saved_refresh.family_id, nonce=new_nonce
    )
    refresh_token = encrypt_refresh(refresh_key, refresh)
    return refresh_token


def create_tokens(
    user_id: str,
    scope: str,
    auth_time: int,
    id_nonce: str,
    utc_now: int,
    id_info: IdInfo,
    issuer: str,
    frontend_client_id: str,
    backend_client_id: str,
    refresh_exp: int,
):
    # Build new tokens
    access_token_data, id_token_core_data = id_access_tokens(
        sub=user_id,
        iss=issuer,
        aud_access=[frontend_client_id, backend_client_id],
        aud_id=[frontend_client_id],
        scope=scope,
        auth_time=auth_time,
        id_nonce=id_nonce,
    )

    # Scope to be returned in response
    access_scope = access_token_data.scope

    # Encoded tokens to store for refresh token
    access_val_encoded = encode_token_dict(access_token_data.model_dump())
    id_token_dict = add_info_to_id(id_token_core_data, id_info)
    id_token_val_encoded = encode_token_dict(id_token_dict)
    # Each authentication creates a refresh token of a particular family, which
    # has a static lifetime
    family_id = secrets.token_urlsafe(16)
    refresh_save = SavedRefreshToken(
        family_id=family_id,
        access_value=access_val_encoded,
        id_token_value=id_token_val_encoded,
        exp=utc_now + refresh_exp,
        iat=utc_now,
        nonce="",
        user_id=user_id,
    )
    return access_token_data, id_token_core_data, access_scope, refresh_save


def finish_tokens(
    refresh_id: int,
    refresh_save: SavedRefreshToken,
    refresh_key: SymmetricKey,
    access_token_data: SavedAccessToken,
    id_token_data: IdToken,
    id_info: IdInfo,
    utc_now: int,
    signing_key: PEMPrivateKey,
    access_exp: int,
    id_exp: int,
    *,
    nonce: str,
):
    refresh = RefreshToken(id=refresh_id, family_id=refresh_save.family_id, nonce=nonce)
    refresh_token = encrypt_refresh(refresh_key, refresh)

    access_token = finish_encode_token(
        access_token_data.model_dump(), utc_now, access_exp, signing_key
    )
    id_token_dict = add_info_to_id(id_token_data, id_info)
    id_token = finish_encode_token(id_token_dict, utc_now, id_exp, signing_key)

    return refresh_token, access_token, id_token


def id_access_tokens(sub, iss, aud_access, aud_id, scope, auth_time, id_nonce):
    """Create ID and access token objects."""
    access_core = SavedAccessToken(sub=sub, iss=iss, aud=aud_access, scope=scope)
    id_core = IdToken(
        sub=sub,
        iss=iss,
        aud=aud_id,
        auth_time=auth_time,
        nonce=id_nonce,
    )

    return access_core, id_core


def add_info_to_id(id_token: IdToken, id_info: IdInfo):
    return id_token.model_dump() | id_info.model_dump()
