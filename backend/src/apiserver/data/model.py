
import sqlalchemy as sqla
from typing import TypedDict
from dataclasses import dataclass

# Helps name constraints
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = sqla.MetaData(naming_convention=convention)

@dataclass(frozen=True)
class UserTable:
    NAME = "user"
    INT_ID = "id"
    NAME_ID = "id_name"
    ID = "user_id"
    EMAIL = "email"
    FIRSTNAME = "firstname"
    LASTNAME = "lastname"
    PASSWORD_HASH = "password_hash"
    PASSWORD_SALT = "password_salt"
    PASSWORD_HASH_ALGORITHM_ID = "password_hash_algorithm_id"
    DISABLED = "disabled"
    EMAIL_ADDRESS_COUNTER = "email_address_counter"
    PASSWORD_HASH_COUNTER = "password_hash_counter"
    DISABLED_COUNTER = "disabled_counter"
    SESSIONS_COUNTER = "sessions_counter"


@dataclass(frozen=True)
class NewUserTable:
    NAME = "newuser"
    EMAIL = "email"
    FIRSTNAME = "firstname"
    LASTNAME = "lastname"
    ACCEPTED = "accepted"

compute_text = sqla.text(f"CAST({UserTable.INT_ID} AS TEXT) || '_' || {UserTable.NAME_ID}")
users = sqla.Table(
    UserTable.NAME,
    metadata,
    # binary int of usp_hex
    sqla.Column(UserTable.INT_ID, sqla.Integer, primary_key=True),
    sqla.Column(UserTable.NAME_ID, sqla.Text, nullable=False),
    sqla.Column(
        UserTable.ID,
        sqla.Text,
        sqla.Computed(compute_text, persisted=True),
        unique=True,
        nullable=False,
        index=True,
    ),
    sqla.Column(
        UserTable.EMAIL, sqla.Text, unique=True, nullable=False, index=True
    ),
    sqla.Column(UserTable.FIRSTNAME, sqla.Text, nullable=False),
    sqla.Column(UserTable.LASTNAME, sqla.Text, nullable=False),
    sqla.Column(UserTable.PASSWORD_HASH, sqla.LargeBinary, nullable=False),
    sqla.Column(UserTable.PASSWORD_SALT, sqla.LargeBinary, nullable=False),
    sqla.Column(UserTable.PASSWORD_HASH_ALGORITHM_ID, sqla.Text, nullable=False),
    sqla.Column(UserTable.DISABLED, sqla.Integer, nullable=False, default=0),
    sqla.Column(UserTable.EMAIL_ADDRESS_COUNTER, sqla.Integer, nullable=False, default=0),
    sqla.Column(UserTable.PASSWORD_HASH_COUNTER, sqla.Integer, nullable=False, default=0),
    sqla.Column(UserTable.DISABLED_COUNTER, sqla.Integer, nullable=False, default=0),
    sqla.Column(UserTable.SESSIONS_COUNTER, sqla.Integer, nullable=False, default=0),
    sqlite_with_rowid=False,
    sqlite_strict=True
)

newusers = sqla.Table(
    NewUserTable.NAME,
    metadata,
    sqla.Column(NewUserTable.EMAIL, sqla.Text, primary_key=True),
    sqla.Column(NewUserTable.FIRSTNAME, sqla.Text, nullable=False),
    sqla.Column(NewUserTable.LASTNAME, sqla.Text, nullable=False),
    sqla.Column(NewUserTable.ACCEPTED, sqla.Integer, nullable=False, default=0),
    sqlite_with_rowid=False,
    sqlite_strict=True
)

# KEY_TABLE = "keys"
# KEY_ID = "kid"
# KEY_ISSUED = "iat"
# KEY_USE = "use"
# keys = sqla.Table(
#     KEY_TABLE,
#     metadata,
#     sqla.Column(KEY_ID, sqla.String(length=50), primary_key=True),
#     sqla.Column(KEY_ISSUED, sqla.Integer, nullable=False),
#     sqla.Column(KEY_USE, sqla.String(length=50), nullable=False),
# )

# JWK_TABLE = "jwk"
# JWK_VALUE = "encrypted_value"

# jwk = sqla.Table(
#     JWK_TABLE,
#     metadata,
#     sqla.Column(
#         "id",
#         sqla.Integer,
#         sqla.CheckConstraint("id = 1", name="check_single"),
#         primary_key=True,
#     ),
#     sqla.Column(JWK_VALUE, sqla.String, nullable=False),
# )

# OPAQUE_SETUP_TABLE = "opaque"
# OPAQUE_VALUE = "value"

# opaque_setup = sqla.Table(
#     OPAQUE_SETUP_TABLE,
#     metadata,
#     sqla.Column("id", sqla.Integer, primary_key=True),
#     sqla.Column(OPAQUE_VALUE, sqla.String(length=300), nullable=False),
# )

# REFRESH_TOKEN_TABLE = "refreshtokens"
# FAMILY_ID = "family_id"
# ACCESS_VALUE = "access_value"
# ID_TOKEN_VALUE = "id_token_value"
# EXPIRATION = "exp"
# NONCE = "nonce"
# ISSUED_AT = "iat"
# refreshtokens = sqla.Table(
#     REFRESH_TOKEN_TABLE,
#     metadata,
#     sqla.Column("id", sqla.Integer, primary_key=True),
#     sqla.Column(
#         USER_ID,
#         sqla.String(length=150),
#         sqla.ForeignKey(f"{USER_TABLE}.{USER_ID}", ondelete="CASCADE"),
#         nullable=False,
#     ),
#     sqla.Column(FAMILY_ID, sqla.String(length=200), nullable=False),
#     sqla.Column(ACCESS_VALUE, sqla.String(length=1000), nullable=False),
#     sqla.Column(ID_TOKEN_VALUE, sqla.String(length=1000), nullable=False),
#     sqla.Column(EXPIRATION, sqla.Integer, nullable=False),
#     sqla.Column(ISSUED_AT, sqla.Integer, nullable=False),
#     sqla.Column(NONCE, sqla.String(length=200)),
# )

# USERDATA_TABLE = "userdata"
# # whether or not they are an active member
# UD_ACTIVE = "active"
# UD_FIRSTNAME = "firstname"
# UD_LASTNAME = "lastname"
# UD_EMAIL = "email"
# JOINED = "joined"
# BIRTHDATE = "birthdate"
# SHOW_AGE = "showage"
# CONFIRMED = "confirmed"
# userdata = sqla.Table(
#     USERDATA_TABLE,
#     metadata,
#     sqla.Column(
#         USER_ID,
#         sqla.String(length=150),
#         sqla.ForeignKey(f"{USER_TABLE}.{USER_ID}", ondelete="CASCADE"),
#         primary_key=True,
#     ),
#     sqla.Column(UD_ACTIVE, sqla.Boolean, nullable=False),
#     sqla.Column(UD_FIRSTNAME, sqla.String(length=100), nullable=False),
#     sqla.Column(UD_LASTNAME, sqla.String(length=100), nullable=False),
#     sqla.Column(
#         UD_EMAIL,
#         sqla.String(length=255),
#         sqla.ForeignKey(
#             f"{USER_TABLE}.{USER_EMAIL}", ondelete="CASCADE", onupdate="CASCADE"
#         ),
#         unique=True,
#         nullable=False,
#     ),
#     sqla.Column(CONFIRMED, sqla.Boolean, default=False),
#     sqla.Column(JOINED, sqla.Date),
#     sqla.Column(BIRTHDATE, sqla.Date, nullable=False),
#     sqla.Column(SHOW_AGE, sqla.Boolean),
# )

# CLASSIFICATION_TABLE = "classifications"
# CLASS_ID = "classification_id"
# CLASS_TYPE = "type"
# CLASS_START_DATE = "start_date"
# CLASS_END_DATE = "end_date"
# CLASS_HIDDEN_DATE = "hidden_date"
# CLASS_LAST_UPDATED = "last_updated"
# classification = sqla.Table(
#     CLASSIFICATION_TABLE,
#     metadata,
#     # Maybe we want to change this (the id) to a String
#     # So we can have an ID like: Training_2023
#     # That will make it more usable for non programmers.
#     sqla.Column(CLASS_ID, sqla.Integer, primary_key=True),
#     sqla.Column(CLASS_TYPE, sqla.String(length=100), nullable=False),
#     sqla.Column(CLASS_START_DATE, sqla.DateTime, nullable=False),
#     sqla.Column(CLASS_END_DATE, sqla.DateTime, nullable=False),
#     sqla.Column(CLASS_HIDDEN_DATE, sqla.DateTime, nullable=False),
#     sqla.Column(CLASS_LAST_UPDATED, sqla.DateTime, nullable=True),
# )

# MAX_EVENT_ID_LEN = 30
# CLASS_EVENTS_TABLE = "class_events"
# C_EVENTS_ID = "event_id"
# # CLASS_ID is a foreign key
# C_EVENTS_CATEGORY = "category"
# C_EVENTS_DESCRIPTION = "description"
# C_EVENTS_DATE = "date"
# class_events = sqla.Table(
#     CLASS_EVENTS_TABLE,
#     metadata,
#     sqla.Column(
#         C_EVENTS_ID,
#         sqla.String(length=MAX_EVENT_ID_LEN),
#         primary_key=True,
#     ),
#     sqla.Column(
#         CLASS_ID,
#         sqla.Integer,
#         sqla.ForeignKey(f"{CLASSIFICATION_TABLE}.{CLASS_ID}", ondelete="SET NULL"),
#         nullable=True,
#     ),
#     sqla.Column(C_EVENTS_CATEGORY, sqla.String(length=100), nullable=False),
#     sqla.Column(C_EVENTS_DESCRIPTION, sqla.String(length=500)),
#     sqla.Column(C_EVENTS_DATE, sqla.DateTime, nullable=False),
#     sqla.Column(
#         "32",
#         sqla.Integer,
#         sqla.ForeignKey(f"{CLASSIFICATION_TABLE}.{CLASS_ID}", ondelete="SET NULL"),
#         nullable=True,
#     ),
# )

# CLASS_EVENTS_POINTS_TABLE = "class_event_points"
# # C_EVENTS_ID is foreign key
# # USER_ID is foreign key
# C_EVENTS_POINTS = "points"
# class_events_points = sqla.Table(
#     CLASS_EVENTS_POINTS_TABLE,
#     metadata,
#     sqla.Column(
#         USER_ID,
#         sqla.String(length=150),
#         sqla.ForeignKey(f"{USER_TABLE}.{USER_ID}", ondelete="CASCADE"),
#         primary_key=True,
#     ),
#     sqla.Column(
#         C_EVENTS_ID,
#         sqla.String(length=30),
#         sqla.ForeignKey(f"{CLASS_EVENTS_TABLE}.{C_EVENTS_ID}", ondelete="CASCADE"),
#         primary_key=True,
#     ),
#     sqla.Column(C_EVENTS_POINTS, sqla.Integer, nullable=False),
# )

# CLASS_POINTS_TABLE = "class_points"
# # USER_ID is foreign key
# # CLASS_ID is foreign key
# TRUE_POINTS = "true_points"
# DISPLAY_POINTS = "display_points"
# class_punten = sqla.Table(
#     CLASS_POINTS_TABLE,
#     metadata,
#     sqla.Column(
#         USER_ID,
#         sqla.String(length=150),
#         sqla.ForeignKey(f"{USER_TABLE}.{USER_ID}", ondelete="CASCADE"),
#         primary_key=True,
#     ),
#     sqla.Column(
#         CLASS_ID,
#         sqla.Integer,
#         sqla.ForeignKey(f"{CLASSIFICATION_TABLE}.{CLASS_ID}", ondelete="CASCADE"),
#         primary_key=True,
#     ),
#     sqla.Column(TRUE_POINTS, sqla.Integer, nullable=False),
#     sqla.Column(DISPLAY_POINTS, sqla.Integer, nullable=False),
# )

# CONTENT_TABLE = "content"
# CONTENT_ID = "content_id"
# CONTENT_CATEGORY = "category"
# CONTENT_DATA = "data"
# content = sqla.Table(
#     CONTENT_TABLE,
#     metadata,
#     sqla.Column(CONTENT_ID, sqla.String(length=150), primary_key=True),
#     sqla.Column(CONTENT_CATEGORY, sqla.String(length=150), primary_key=True),
#     sqla.Column(CONTENT_DATA, sqla.JSON),
# )
