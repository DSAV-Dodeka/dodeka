import sqlite3
from sqlalchemy.exc import IntegrityError


def check_integrity_error(e: IntegrityError, column: str, category: str) -> bool:
    """For column 'email' in table 'user', 'user.email' would be the column. For category, at least 'unique' works."""
    orig = e.orig
    assert isinstance(orig, sqlite3.IntegrityError)
    assert isinstance(orig.args[0], str)
    return column in orig.args[0] and category in orig.args[0].lower()
