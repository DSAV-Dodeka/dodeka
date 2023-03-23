from pathlib import Path
from typing import Optional, Union, Any
import json
from base64 import urlsafe_b64encode, urlsafe_b64decode
import sys
import time
import hashlib
import secrets
import math
import regex as re
from datetime import datetime, timezone


def random_time_hash_hex(
    extra_seed: Optional[Union[bytes, str]] = None, short: bool = False
) -> str:
    """Random string (bound to timestamp and optional extra seed) to represent events/objects that must be uniquely
    identified. These should not be used for security."""
    if isinstance(extra_seed, str):
        extra_seed = extra_seed.encode("utf-8")

    timestamp = time.time_ns().to_bytes(10, byteorder="big")
    random_bytes = (
        (extra_seed if extra_seed is not None else b"")
        + secrets.token_bytes(10)
        + timestamp
    )
    hashed = hashlib.shake_256(random_bytes)
    if short:
        return hashed.hexdigest(8)
    else:
        return hashed.hexdigest(16)


urlsafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_"
urlsafe_set = set(
    [int.from_bytes(c.encode("utf-8"), byteorder=sys.byteorder) for c in urlsafe]
)

rad64_dict = urlsafe + "~"


# urlsafe-preserving hex
def usp_hex(unicode_str: str) -> str:
    """It is nice to internally use an urlsafe (i.e. only using characters that don't have to be percent-encoded (e.g.
    @ becomes %40) representations of Unicode usernames that preserves some common, urlsafe characters, making it more
    readable. It might be a good idea to write accelerated Rust extensions for this in the future if it proves to be
    slow."""
    anp_base64url_str = ""
    encoded_str = unicode_str.encode(encoding="utf-8")
    for e in encoded_str:
        if e in urlsafe_set:
            anp_base64url_str += e.to_bytes(1, byteorder=sys.byteorder).decode(
                encoding="utf-8"
            )
        else:
            # the 'x' in the format string indicates hex
            anp_base64url_str += "~" + f"{e:x}"

    return anp_base64url_str


HEX_PER_BYTE = 2


def de_usp_hex(usp_hex_str: str) -> str:
    """Reverse of usp_hex, returns the utf-8 string."""
    b_str = b""

    hex_chars = ""
    hexing = False
    for c in usp_hex_str:
        if c == "~":
            hexing = True
        elif hexing:
            hex_chars += c
            if len(hex_chars) == HEX_PER_BYTE:
                b_str += bytes.fromhex(hex_chars)
                hex_chars = ""
                hexing = False
        else:
            b_str += c.encode("utf-8")

    return b_str.decode("utf-8")


"""START LICENSED CODE
Copyright (c) 2012 Kevin Gillette. All rights reserved.
Licensed under BSD 3-Clause "New" or "Revised" License

This code has been modified."""

urlsafe_table = dict((c, i) for i, c in enumerate(rad64_dict))


def _rad64_enc(n: int) -> str:
    out = ""
    while n > 0:
        out = rad64_dict[n & 63] + out
        n >>= 6
    return out


def _rad64_dec(rad64_cs: str) -> int:
    n = 0
    for c in rad64_cs:
        got_c = urlsafe_table.get(c)
        if got_c is None:
            raise ValueError("Invalid character in input: " + c)
        n = n << 6 | got_c
    return n


"""END LICENSED CODE"""


def rad64_frombytes(b: bytes) -> str:
    return _rad64_enc(int.from_bytes(b, byteorder="big"))


def rad64_tobytes(s: str) -> bytes:
    by = _rad64_dec(s)
    byte_len = math.ceil(by.bit_length() / 8)
    return by.to_bytes(byteorder="big", length=byte_len)


def usp_hex_bin(usp_hex_str: str) -> bytes:
    return rad64_tobytes(usp_hex_str)


def usp_hex_debin(usp_hex_bytes: bytes) -> str:
    return rad64_frombytes(usp_hex_bytes)


def add_base64_padding(unpadded: str) -> str:
    while len(unpadded) % 4 != 0:
        unpadded += "="
    return unpadded


def enc_b64url(b: bytes) -> str:
    """
    Encodes bytes to a base64url-encoded string with no padding.
    """
    return urlsafe_b64encode(b).decode("utf-8").rstrip("=")


def dec_b64url(s: str) -> bytes:
    """
    Decodes a base64url-encoded string to bytes.
    """
    b64_bytes = add_base64_padding(s).encode("utf-8")
    return urlsafe_b64decode(b64_bytes)


def utc_timestamp() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def enc_dict(dct: dict[str, Any]) -> bytes:
    """Convert dict to UTF-8-encoded bytes in JSON format."""
    return json.dumps(dct).encode("utf-8")


def dec_dict(encoded: bytes) -> dict[str, Any]:
    """Convert UTF-8 bytes containing JSON to a dict."""
    obj = json.loads(encoded.decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("Only supports JSON objects, not primitives.")
    return obj


def when_modified(p: Path) -> int:
    """Calculates the timestamp of most recently modified file in all files,
    subdirectories in a path.
    """
    return max([int(f.stat().st_mtime) if f.is_file() else 0 for f in p.rglob("*")])


def strip_edge(string: str):
    string.rstrip()
    # \s is all whitespace
    # \p{Z} is all unicode whitespace
    # \p{C} is all kinds of nasty control and zero-width characters
    match_string = r"[\s\p{Z}\p{C}]+"
    # ^ start of string
    # $ end of string
    return re.sub(f"^{match_string}|{match_string}$", "", string)
