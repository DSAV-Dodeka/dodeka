import secrets
import json
from secrets import token_urlsafe
from base64 import urlsafe_b64decode, urlsafe_b64encode

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import ValidationError
import jwt
from jwt import PyJWTError

from dodekaserver.utilities import add_base64_padding, encb64url_str, decb64url_str, utc_timestamp
import dodekaserver.data as data
from dodekaserver.data.entities import SavedRefreshToken, RefreshToken, AccessToken, IdToken
from dodekaserver.data import Source, DataError

__all__ = ['create_id_access_refresh', 'verify_access_token', 'InvalidRefresh']

id_exp = 10 * 60 * 60  # 10 hours
access_exp = 1 * 60 * 60  # 1 hour
refresh_exp = 30 * 24 * 60 * 60  # 1 month

grace_period = 3 * 60  # 3 minutes in which it is still accepted

issuer = "https://dsavdodeka.nl/auth"
backend_client_id = "dodekabackend_client"


def _encode_json_dict(dct: dict) -> bytes:
    """ Convert dict to UTF-8-encoded bytes in JSON format. """
    return json.dumps(dct).encode('utf-8')


def _decode_json_dict(encoded: bytes) -> dict:
    """ Convert UTF-8 bytes containing JSON to a dict. """
    return json.loads(encoded.decode('utf-8'))


class InvalidRefresh(Exception):
    """ Invalid refresh token. """
    pass


def encrypt_refresh(aesgcm: AESGCM, refresh: RefreshToken) -> str:
    refresh_data = _encode_json_dict(refresh.dict())
    refresh_nonce = secrets.token_bytes(12)
    encrypted = aesgcm.encrypt(refresh_nonce, refresh_data, None)
    refresh_bytes = refresh_nonce + encrypted
    return urlsafe_b64encode(refresh_bytes).decode('utf-8').rstrip("=")


def decrypt_refresh(aesgcm: AESGCM, refresh_token) -> RefreshToken:
    padded_refresh_token = add_base64_padding(refresh_token)
    refresh_bytes = urlsafe_b64decode(padded_refresh_token.encode('utf-8'))
    refresh_nonce = refresh_bytes[:12]
    refresh_data = refresh_bytes[12:]
    decrypted = aesgcm.decrypt(refresh_nonce, refresh_data, None)
    refresh_dict = _decode_json_dict(decrypted)
    return RefreshToken.parse_obj(refresh_dict)


async def create_id_access_refresh(dsrc: Source, user_usph: str = None, scope: str = None, id_nonce: str = None,
                                   auth_time: int = None, old_refresh_token: str = None):
    """
    If the refresh_token is given, it will swap the refresh_token for a new refresh token from the same family and with
    the same expiration date. It will also provide a fresh access token and ID token.

    Otherwise, it will create a new refresh token and accompanying access and ID tokens, using the provided info.

    Use this function with extreme care, only ever create a refresh token after authentication.

    :return: Tuple of access token, refresh token, token_type, access expiration in seconds, scope, respectively.
    """
    # ENSURE scope is validated by the server first, do not pass directly from client

    # Symmetric key used to verify and encrypt/decrypt refresh tokens
    symmetric_key = await data.key.get_refresh_symmetric(dsrc)
    # We store it unpadded (to match convention of not storing padding throughout the DB)
    padded_symmetric_key = add_base64_padding(symmetric_key)
    symmetric_key_bytes = urlsafe_b64decode(padded_symmetric_key.encode('utf-8'))
    # Fernet is a helper class from Python cryptography that does the encrypting/decrypting
    # We load it with the key from our database
    aesgcm = AESGCM(symmetric_key_bytes)
    # Asymmetric private key used for signing access and ID tokens
    # A public key is then used to verify them
    signing_key = await data.key.get_token_private(dsrc)

    utc_now = utc_timestamp()

    token_type = "Bearer"

    if old_refresh_token is not None:
        # expects base64url-encoded binary
        try:
            # If it has been tampered with, this will also give an error
            old_refresh = decrypt_refresh(aesgcm, old_refresh_token)
        except InvalidToken:
            # Fernet error or signature error, could also be key format
            raise InvalidRefresh
        except ValidationError:
            # From parsing the dict
            raise InvalidRefresh
        except ValueError:
            # For example from the JSON decoding
            raise InvalidRefresh

        try:
            # See if previous refresh exists
            saved_refresh = await data.refreshtoken.get_refresh_by_id(dsrc, old_refresh.id)
        except DataError as e:
            if e.key != "refresh_empty":
                # If not refresh_empty, it was some other internal error
                raise e
            # Only the most recent token should be valid and is always returned
            # So if someone possesses some deleted token family member, it is most likely an attacker
            # For this reason, all tokens in the family are invalidated to prevent further compromise
            await data.refreshtoken.delete_family(dsrc, old_refresh.family_id)
            raise InvalidRefresh

        if saved_refresh.nonce != old_refresh.nonce or saved_refresh.family_id != old_refresh.family_id:
            raise InvalidRefresh
        elif saved_refresh.iat > utc_now or saved_refresh.iat < 1640690242:
            # sanity check
            raise InvalidRefresh
        elif utc_now > saved_refresh.exp + grace_period:
            # refresh no longer valid
            raise InvalidRefresh

        # Rebuild access and ID tokens from value in refresh token
        # We need the core static info to rebuild with new iat, etc.
        saved_access_dict = _decode_json_dict(decb64url_str(saved_refresh.access_value))
        saved_access = AccessToken.parse_obj(saved_access_dict)
        saved_id_token_dict = _decode_json_dict(decb64url_str(saved_refresh.id_token_value))
        saved_id_token = IdToken.parse_obj(saved_id_token_dict)
        # Add new expiry, iat
        new_access_payload = finish_token(saved_access.dict(), utc_now)
        new_id_token_payload = finish_token(saved_id_token.dict(), utc_now)

        # Scope to be returned in response
        access_scope = saved_access.scope

        # Create JWTs from tokens
        access_token = jwt.encode(new_access_payload, signing_key, algorithm="EdDSA")
        id_token = jwt.encode(new_id_token_payload, signing_key, algorithm="EdDSA")

        # Nonce is used to make it impossible to 'guess' new refresh tokens
        # (So it becomes a combination of family_id + id nr + nonce)
        # Although signing and encrypting should also protect it from that
        new_nonce = token_urlsafe(16)
        # We don't store the access tokens and refresh tokens in the final token
        # To construct new tokens, we need that information so we save it in the DB
        new_refresh_save = SavedRefreshToken(family_id=saved_refresh.family_id,
                                             access_value=saved_refresh.access_value,
                                             id_token_value=saved_refresh.id_token_value, exp=saved_refresh.exp,
                                             iat=utc_now, nonce=new_nonce)
        # Deletes previous token, saves new one, only succeeds if all components of the transaction succeed
        new_refresh_id = await data.refreshtoken.refresh_transaction(dsrc, saved_refresh.id, new_refresh_save)

        # The actual refresh token is an encrypted JSON dictionary containing the id, family_id and nonce
        refresh = RefreshToken(id=new_refresh_id, family_id=saved_refresh.family_id, nonce=new_nonce)
        refresh_token = encrypt_refresh(aesgcm, refresh)
    else:
        assert user_usph is not None
        assert scope is not None
        assert id_nonce is not None
        assert auth_time is not None

        # Build new tokens
        access_val, id_token_val = id_access_tokens(sub=user_usph,
                                                    iss="https://dsavdodeka.nl/auth",
                                                    aud_access=["dodekaweb_client", "dodekabackend_client"],
                                                    aud_id=["dodekaweb_client"],
                                                    scope=scope,
                                                    auth_time=auth_time,
                                                    id_nonce=id_nonce)

        # Scope to be returned in response
        access_scope = access_val.scope

        # Encoded tokens to store for refresh token
        access_val_encoded = encb64url_str(_encode_json_dict(access_val.dict()))
        id_token_val_encoded = encb64url_str(_encode_json_dict(id_token_val.dict()))
        # Each authentication creates a refresh token of a particular family, which has a static lifetime
        family_id = secrets.token_urlsafe(16)
        refresh_save = SavedRefreshToken(family_id=family_id, access_value=access_val_encoded,
                                         id_token_value=id_token_val_encoded, exp=utc_now + refresh_exp, iat=utc_now,
                                         nonce="")
        refresh_id = await data.refreshtoken.refresh_save(dsrc, refresh_save)
        refresh = RefreshToken(id=refresh_id, family_id=refresh_save.family_id, nonce="")
        refresh_token = encrypt_refresh(aesgcm, refresh)

        access_payload = finish_token(access_val.dict(), utc_now)
        id_token_payload = finish_token(id_token_val.dict(), utc_now)

        access_token = jwt.encode(access_payload, signing_key, algorithm="EdDSA")
        id_token = jwt.encode(id_token_payload, signing_key, algorithm="EdDSA")

    return id_token, access_token, refresh_token, token_type, access_exp, access_scope


def id_access_tokens(sub, iss, aud_access, aud_id, scope, auth_time, id_nonce):
    """ Create ID and access token objects. """
    access_core = AccessToken(sub=sub,
                              iss=iss,
                              aud=aud_access,
                              scope=scope)
    id_core = IdToken(sub=sub,
                      iss=iss,
                      aud=aud_id,
                      auth_time=auth_time,
                      nonce=id_nonce)

    return access_core, id_core


def finish_token(token_val: dict, utc_now: int):
    """ Add time-based information to static token dict. """
    payload_add = {
        "iat": utc_now,
        "exp": utc_now + access_exp,
    }
    payload = dict(token_val, **payload_add)
    return payload


class BadVerification(Exception):
    """ Error during token verification. """
    pass


def verify_access_token(public_key: str, access_token: str):
    try:
        decoded_payload = jwt.decode(access_token, public_key, algorithms=["EdDSA"], leeway=grace_period,
                                     require=["exp", "aud"], issuer=issuer, audience=[backend_client_id])
    except PyJWTError as e:
        # TODO specify correct errors for return info
        print(e)
        raise BadVerification

    return AccessToken.parse_obj(decoded_payload)
