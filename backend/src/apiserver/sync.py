"""Sync operations for importing member data from the Atletiekunie CSV export.

Implements the spec's pending sync session model:
  - import_sync starts a session (sync_state, sync, sync_decisions)
  - resolve_sync_match records a pending decision in sync_decisions
  - complete_sync applies everything atomically in one storage callback
"""

import csv
import io
import json
import logging
import time as time_mod
from dataclasses import dataclass
from datetime import date, datetime

from freetser import Storage

from apiserver.data.features.birthdays import replace_birthdays
from apiserver.data.outbox import create_outbox_row
from apiserver.data.permissions import (
    Permissions,
    add_permission,
    remove_permission,
)
from apiserver.data.registrations import (
    Registration,
    create_or_reuse_registration,
    get_registration,
    get_registration_by_bondsnummer,
    list_registrations,
    migrate_registration_email,
    normalize_email,
    upsert_registration,
)
from apiserver.data.user import UserInfo, list_all_users
from apiserver.data.userdata import (
    BONDSNUMMER_TABLE,
    SYNC_TABLE,
    VOLTA_DATA_TABLE,
    VoltaFieldDiff,
    VoltaRow,
    compute_field_diffs,
    delete_user_bondsnummer,
    get_bondsnummer_by_user_id,
    get_user_id_by_bondsnummer,
    get_volta,
    list_volta,
    set_user_bondsnummer,
    upsert_volta,
    volta_to_dict,
)

logger = logging.getLogger("apiserver.sync")

SYSTEM_USERS_TABLE = "system_users"
SYNC_STATE_TABLE = "sync_state"
SYNC_DECISIONS_TABLE = "sync_decisions"
SYNC_STATE_KEY = "current"

MAX_CANDIDATES = 5


# ---------------------------------------------------------------------------
# Sync state helpers
# ---------------------------------------------------------------------------


@dataclass
class StaleCounter:
    message: str


@dataclass
class SyncStateInfo:
    in_progress: bool
    counter: int
    file_modified_at: int | None


def get_sync_state(store: Storage) -> SyncStateInfo:
    """Return sync session state."""
    result = store.get(SYNC_STATE_TABLE, SYNC_STATE_KEY)
    if result is None:
        return SyncStateInfo(in_progress=False, counter=0, file_modified_at=None)
    data, counter = result
    d = json.loads(data.decode("utf-8"))
    return SyncStateInfo(
        in_progress=d.get("in_progress", False),
        counter=counter,
        file_modified_at=d.get("file_modified_at"),
    )


def set_sync_state(
    store: Storage, in_progress: bool, file_modified_at: int | None = None
) -> None:
    """Overwrite sync_state (advances the freetser counter)."""
    state: dict[str, object] = {"in_progress": in_progress}
    if file_modified_at is not None:
        state["file_modified_at"] = file_modified_at
    data = json.dumps(state).encode("utf-8")
    store.overwrite(SYNC_STATE_TABLE, SYNC_STATE_KEY, data, expires_at=0)


def advance_sync_state(
    store: Storage,
    expected_counter: int,
    in_progress: bool,
    file_modified_at: int | None = None,
) -> None:
    """Check counter and write new state via update().

    Raises UpdateCounterMismatch if the caller's counter doesn't match,
    which causes freetser to roll back the entire callback.
    """
    state: dict[str, object] = {"in_progress": in_progress}
    if file_modified_at is not None:
        state["file_modified_at"] = file_modified_at
    data = json.dumps(state).encode("utf-8")
    store.update(
        SYNC_STATE_TABLE,
        SYNC_STATE_KEY,
        data,
        expected_counter,
        expires_at=0,
    )


# ---------------------------------------------------------------------------
# Sync decisions helpers
# ---------------------------------------------------------------------------


@dataclass
class SyncDecision:
    kind: str  # "registration", "user", "none"
    subject_id: str | None


def store_decision(store: Storage, bondsnummer: int, decision: SyncDecision) -> None:
    data = json.dumps(
        {
            "kind": decision.kind,
            "subject_id": decision.subject_id,
        }
    ).encode("utf-8")
    store.overwrite(SYNC_DECISIONS_TABLE, str(bondsnummer), data, expires_at=0)


def get_decision(store: Storage, bondsnummer: int) -> SyncDecision | None:
    result = store.get(SYNC_DECISIONS_TABLE, str(bondsnummer))
    if result is None:
        return None
    d = json.loads(result[0].decode("utf-8"))
    return SyncDecision(kind=d["kind"], subject_id=d.get("subject_id"))


def list_decisions(store: Storage) -> dict[int, SyncDecision]:
    decisions: dict[int, SyncDecision] = {}
    for key in store.list_keys(SYNC_DECISIONS_TABLE):
        result = store.get(SYNC_DECISIONS_TABLE, key)
        if result is not None:
            d = json.loads(result[0].decode("utf-8"))
            decisions[int(key)] = SyncDecision(
                kind=d["kind"], subject_id=d.get("subject_id")
            )
    return decisions


# ---------------------------------------------------------------------------
# Cancellation check
# ---------------------------------------------------------------------------


def is_cancelled(opzegdatum: str, today: date | None = None) -> bool:
    if not opzegdatum:
        return False
    try:
        cancel_date = datetime.strptime(opzegdatum, "%d/%m/%Y").date()
    except ValueError:
        return False
    if today is None:
        today = date.today()
    return cancel_date <= today


# ---------------------------------------------------------------------------
# CSV Parsing
# ---------------------------------------------------------------------------


def parse_csv(content: str) -> list[VoltaRow]:
    if content.startswith("\ufeff"):
        content = content[1:]

    # Some exports wrap each data row in outer quotes — unwrap them so
    # csv.DictReader can parse the fields correctly.
    lines = content.splitlines()
    if lines:
        cleaned_lines = [lines[0].strip()]
        for line in lines[1:]:
            stripped = line.strip()
            if stripped.startswith('"') and stripped.endswith('"'):
                stripped = stripped[1:-1].replace('""', '"')
            cleaned_lines.append(stripped)
        content = "\n".join(cleaned_lines)

    entries = []
    reader = csv.DictReader(io.StringIO(content))
    if reader.fieldnames is not None:
        for row in reader:
            email = normalize_email(row.get("Email", ""))
            bondsnummer_raw = row.get("Bondsnummer", "").strip()
            try:
                bondsnummer = int(bondsnummer_raw) if bondsnummer_raw else 0
            except ValueError:
                bondsnummer = 0
            entries.append(
                VoltaRow(
                    bondsnummer=bondsnummer,
                    voornaam=row.get("Voornaam", "").strip(),
                    tussenvoegsel=row.get("Tussenvoegsel", "").strip(),
                    achternaam=row.get("Achternaam", "").strip(),
                    geslacht=row.get("Geslacht", "").strip(),
                    geboortedatum=row.get("Geboortedatum", "").strip(),
                    email=email,
                    opzegdatum=row.get("Club lidmaatschap opzegdatum", "").strip(),
                )
            )
    return entries


# ---------------------------------------------------------------------------
# Import validation
# ---------------------------------------------------------------------------


@dataclass
class ImportValidationError:
    message: str


def validate_import(entries: list[VoltaRow]) -> ImportValidationError | None:
    seen_bondsnummers: set[int] = set()
    seen_emails: set[str] = set()
    for entry in entries:
        if entry.bondsnummer <= 0:
            return ImportValidationError(
                f"Row with email {entry.email} has "
                f"invalid bondsnummer {entry.bondsnummer}"
            )
        email = normalize_email(entry.email)
        if not email:
            return ImportValidationError(
                f"Row with bondsnummer {entry.bondsnummer} has empty email"
            )
        if entry.bondsnummer in seen_bondsnummers:
            return ImportValidationError(f"Duplicate bondsnummer {entry.bondsnummer}")
        if email in seen_emails:
            return ImportValidationError(f"Duplicate email {email}")
        seen_bondsnummers.add(entry.bondsnummer)
        seen_emails.add(email)
    return None


def import_sync(
    store: Storage,
    entries: list[VoltaRow],
    sync_state_counter: int | None = None,
    file_modified_at: int | None = None,
) -> int | ImportValidationError | StaleCounter:
    """Start or overwrite a pending sync session.

    If a session already exists and sync_state_counter is not provided,
    the import is rejected (normal control flow, not a conflict).
    If provided, the counter is checked via update() which raises
    UpdateCounterMismatch on conflict, rolling back the callback.
    """
    error = validate_import(entries)
    if error is not None:
        return error

    state = get_sync_state(store)
    if state.in_progress:
        if sync_state_counter is None:
            return StaleCounter(
                "Pending sync session exists; "
                "pass sync_state_counter to confirm overwrite"
            )
        advance_sync_state(
            store, sync_state_counter, True, file_modified_at=file_modified_at
        )
    else:
        set_sync_state(store, True, file_modified_at=file_modified_at)

    store.clear(SYNC_TABLE)
    store.clear(SYNC_DECISIONS_TABLE)
    for entry in entries:
        upsert_volta(store, SYNC_TABLE, entry)
    return len(entries)


# ---------------------------------------------------------------------------
# System users
# ---------------------------------------------------------------------------


def add_system_user(store: Storage, email: str) -> bool:
    key = normalize_email(email)
    if store.get(SYSTEM_USERS_TABLE, key) is not None:
        return False
    store.add(SYSTEM_USERS_TABLE, key, b"1", expires_at=0)
    return True


def list_system_users(store: Storage) -> list[str]:
    return store.list_keys(SYSTEM_USERS_TABLE)


# ---------------------------------------------------------------------------
# Name normalization for candidate matching
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class NameMatchKey:
    exact: str
    lower: str


def normalize_name_exact(name: str) -> str:
    return " ".join(name.strip().split())


def name_match_key(name: str) -> NameMatchKey:
    exact = normalize_name_exact(name)
    return NameMatchKey(exact=exact, lower=exact.lower())


def names_match(left: NameMatchKey, right: NameMatchKey) -> bool:
    return left.exact == right.exact or left.lower == right.lower


def words_suffix_match(left: str, right: str) -> bool:
    left_words = left.split()
    right_words = right.split()
    if not left_words or not right_words:
        return False
    if len(left_words) < len(right_words):
        left_words, right_words = right_words, left_words
    return left_words[-len(right_words) :] == right_words


def names_suffix_match(left: NameMatchKey, right: NameMatchKey) -> bool:
    return words_suffix_match(left.exact, right.exact) or words_suffix_match(
        left.lower, right.lower
    )


def build_full_name_key_volta(row: VoltaRow) -> NameMatchKey:
    parts = [row.voornaam]
    if row.tussenvoegsel:
        parts.append(row.tussenvoegsel)
    parts.append(row.achternaam)
    return name_match_key(" ".join(parts))


def build_full_name_key_reg(reg: Registration) -> NameMatchKey:
    return name_match_key(f"{reg.firstname} {reg.lastname}")


def build_full_name_key_user(user: UserInfo) -> NameMatchKey:
    return name_match_key(f"{user.firstname} {user.lastname}")


def given_name_prefix_key(name: str) -> NameMatchKey:
    normalized = normalize_name_exact(name)
    return NameMatchKey(exact=normalized[:4], lower=normalized.lower()[:4])


def build_lastname_key_volta(row: VoltaRow) -> NameMatchKey:
    return name_match_key(build_lastname_from_volta(row))


def build_lastname_from_volta(row: VoltaRow) -> str:
    parts = []
    if row.tussenvoegsel:
        parts.append(row.tussenvoegsel)
    parts.append(row.achternaam)
    return " ".join(parts)


# ---------------------------------------------------------------------------
# Candidate generation
# ---------------------------------------------------------------------------


@dataclass
class SyncMatchCandidate:
    kind: str
    subject_id: str
    email: str
    display_name: str
    reasons: list[str]


REASON_ORDER = {
    "email_exact": 0,
    "name_exact": 1,
    "name_partial": 2,
    "name_forgiving": 3,
}


def generate_candidates(
    imported_row: VoltaRow,
    unlinked_registrations: list[Registration],
    unlinked_users: list[UserInfo],
) -> list[SyncMatchCandidate]:
    imported_email = normalize_email(imported_row.email)
    imported_full_name = build_full_name_key_volta(imported_row)
    imported_surname = name_match_key(imported_row.achternaam)
    imported_full_surname = build_lastname_key_volta(imported_row)
    imported_given_prefix = given_name_prefix_key(imported_row.voornaam)

    candidates_map: dict[tuple[str, str], SyncMatchCandidate] = {}

    def add_candidate(
        kind: str, sid: str, email: str, display: str, reason: str
    ) -> None:
        key = (kind, sid)
        if key in candidates_map:
            if reason not in candidates_map[key].reasons:
                candidates_map[key].reasons.append(reason)
        else:
            candidates_map[key] = SyncMatchCandidate(
                kind=kind,
                subject_id=sid,
                email=email,
                display_name=display,
                reasons=[reason],
            )

    for reg in unlinked_registrations:
        e = normalize_email(reg.email)
        fn = build_full_name_key_reg(reg)
        sn = name_match_key(reg.lastname)
        gp = given_name_prefix_key(reg.firstname)
        d = f"{reg.firstname} {reg.lastname}"
        exact_name_match = names_match(fn, imported_full_name)
        partial_name_match = names_match(sn, imported_surname) and names_match(
            gp, imported_given_prefix
        )
        if e == imported_email:
            add_candidate("registration", reg.registration_id, e, d, "email_exact")
        if exact_name_match:
            add_candidate("registration", reg.registration_id, e, d, "name_exact")
        if partial_name_match:
            add_candidate("registration", reg.registration_id, e, d, "name_partial")
        if (
            not exact_name_match
            and not partial_name_match
            and names_suffix_match(sn, imported_full_surname)
            and names_match(gp, imported_given_prefix)
        ):
            add_candidate("registration", reg.registration_id, e, d, "name_forgiving")

    for user in unlinked_users:
        e = normalize_email(user.email)
        fn = build_full_name_key_user(user)
        sn = name_match_key(user.lastname)
        gp = given_name_prefix_key(user.firstname)
        d = f"{user.firstname} {user.lastname}"
        exact_name_match = names_match(fn, imported_full_name)
        partial_name_match = names_match(sn, imported_surname) and names_match(
            gp, imported_given_prefix
        )
        if e == imported_email:
            add_candidate("user", user.user_id, e, d, "email_exact")
        if exact_name_match:
            add_candidate("user", user.user_id, e, d, "name_exact")
        if partial_name_match:
            add_candidate("user", user.user_id, e, d, "name_partial")
        if (
            not exact_name_match
            and not partial_name_match
            and names_suffix_match(sn, imported_full_surname)
            and names_match(gp, imported_given_prefix)
        ):
            add_candidate("user", user.user_id, e, d, "name_forgiving")

    candidates = list(candidates_map.values())

    def sort_key(c: SyncMatchCandidate) -> tuple:
        strongest = min(REASON_ORDER.get(r, 99) for r in c.reasons)
        kind_order = 0 if c.kind == "registration" else 1
        return (strongest, -len(c.reasons), kind_order, c.subject_id)

    candidates.sort(key=sort_key)
    for c in candidates:
        c.reasons.sort(key=lambda r: REASON_ORDER.get(r, 99))

    return candidates[:MAX_CANDIDATES]


# ---------------------------------------------------------------------------
# Read model helpers
# ---------------------------------------------------------------------------


@dataclass
class AdminUserRecord:
    user_id: str
    email: str
    firstname: str
    lastname: str
    permissions: list[str]
    bondsnummer: int | None
    volta_data: dict | None


@dataclass
class AdminRegistrationRecord:
    registration_id: str
    email: str
    firstname: str
    lastname: str
    accepted: bool
    bondsnummer: int | None
    signup_active: bool
    volta_data: dict | None


def make_admin_user_record(
    user: UserInfo, bondsnummer: int | None, volta_data: VoltaRow | None
) -> AdminUserRecord:
    return AdminUserRecord(
        user_id=user.user_id,
        email=user.email,
        firstname=user.firstname,
        lastname=user.lastname,
        permissions=sorted(user.permissions),
        bondsnummer=bondsnummer,
        volta_data=volta_to_dict(volta_data) if volta_data else None,
    )


def make_admin_registration_record(
    reg: Registration, volta_data: VoltaRow | None
) -> AdminRegistrationRecord:
    return AdminRegistrationRecord(
        registration_id=reg.registration_id,
        email=reg.email,
        firstname=reg.firstname,
        lastname=reg.lastname,
        accepted=reg.accepted,
        bondsnummer=reg.bondsnummer,
        signup_active=reg.signup_token is not None,
        volta_data=volta_to_dict(volta_data) if volta_data else None,
    )


def serialize_admin_user(r: AdminUserRecord) -> dict:
    return {
        "user_id": r.user_id,
        "email": r.email,
        "firstname": r.firstname,
        "lastname": r.lastname,
        "permissions": r.permissions,
        "bondsnummer": r.bondsnummer,
        "volta_data": r.volta_data,
    }


def serialize_admin_registration(r: AdminRegistrationRecord) -> dict:
    return {
        "registration_id": r.registration_id,
        "email": r.email,
        "firstname": r.firstname,
        "lastname": r.lastname,
        "accepted": r.accepted,
        "bondsnummer": r.bondsnummer,
        "signup_active": r.signup_active,
        "volta_data": r.volta_data,
    }


def serialize_field_diffs(diffs) -> list[dict]:
    return [
        {"field": d.field, "current": d.current, "incoming": d.incoming} for d in diffs
    ]


def compute_live_user_field_diffs(
    user: UserInfo, current: VoltaRow | None, incoming: VoltaRow
) -> list[VoltaFieldDiff]:
    """Preview the live-user fields complete_sync will actually refresh."""
    diffs = compute_field_diffs(current, incoming)
    incoming_lastname = build_lastname_from_volta(incoming)
    if user.firstname != incoming.voornaam:
        diffs.append(
            VoltaFieldDiff(
                field="profile.firstname",
                current=user.firstname,
                incoming=incoming.voornaam,
            )
        )
    if user.lastname != incoming_lastname:
        diffs.append(
            VoltaFieldDiff(
                field="profile.lastname",
                current=user.lastname,
                incoming=incoming_lastname,
            )
        )
    return diffs


# ---------------------------------------------------------------------------
# Sync status (preview)
# ---------------------------------------------------------------------------


@dataclass
class SyncStatus:
    sync_in_progress: bool
    sync_state_counter: int
    file_modified_at: int | None
    can_complete: bool
    review_required: list[dict]
    registrations_created: list[dict]
    registrations_accepted: list[dict]
    pending_registrations_updated: list[dict]
    live_users_enriched: list[dict]
    departed_users: list[dict]
    volta_data_changes: list[dict]


def compute_sync_status(store: Storage) -> SyncStatus:  # noqa: PLR0912, PLR0915
    state = get_sync_state(store)

    empty = SyncStatus(
        sync_in_progress=False,
        sync_state_counter=state.counter,
        file_modified_at=None,
        can_complete=False,
        review_required=[],
        registrations_created=[],
        registrations_accepted=[],
        pending_registrations_updated=[],
        live_users_enriched=[],
        departed_users=[],
        volta_data_changes=[],
    )
    if not state.in_progress:
        return empty

    timestamp = int(time_mod.time())
    sync_entries = list_volta(store, SYNC_TABLE)
    sync_by_bn = {e.bondsnummer: e for e in sync_entries}
    decisions = list_decisions(store)
    system_emails = set(store.list_keys(SYSTEM_USERS_TABLE))

    all_users = list_all_users(store, timestamp)
    users_by_id = {u.user_id: u for u in all_users}

    user_bn_map: dict[int, str] = {}
    user_to_bn: dict[str, int] = {}
    for key in store.list_keys(BONDSNUMMER_TABLE):
        result = store.get(BONDSNUMMER_TABLE, key)
        if result is not None:
            bn = int(key)
            uid = result[0].decode("utf-8")
            user_bn_map[bn] = uid
            user_to_bn[uid] = bn

    all_regs = list_registrations(store)
    reg_bn_map: dict[int, Registration] = {}
    for reg in all_regs:
        if reg.bondsnummer is not None:
            reg_bn_map[reg.bondsnummer] = reg

    unlinked_regs = [r for r in all_regs if r.bondsnummer is None]
    unlinked_users = [
        u
        for u in all_users
        if u.user_id not in user_to_bn and u.email not in system_emails
    ]

    review_required: list[dict] = []
    registrations_created: list[dict] = []
    registrations_accepted: list[dict] = []
    pending_registrations_updated: list[dict] = []
    live_users_enriched: list[dict] = []
    departed_users: list[dict] = []
    volta_data_changes: list[dict] = []

    # Volta data changes: compare imported snapshot against applied volta_data
    applied_bns = set()
    for key in store.list_keys(VOLTA_DATA_TABLE):
        applied_bns.add(int(key))

    for bn, imported in sync_by_bn.items():
        current = get_volta(store, VOLTA_DATA_TABLE, bn)
        diffs = compute_field_diffs(current, imported)
        if current is not None or True:
            volta_data_changes.append(
                {
                    "bondsnummer": bn,
                    "current_volta_data": volta_to_dict(current) if current else None,
                    "incoming_volta_data": volta_to_dict(imported),
                    "field_diffs": serialize_field_diffs(diffs),
                }
            )

    for bn in applied_bns:
        if bn not in sync_by_bn:
            current = get_volta(store, VOLTA_DATA_TABLE, bn)
            volta_data_changes.append(
                {
                    "bondsnummer": bn,
                    "current_volta_data": volta_to_dict(current) if current else None,
                    "incoming_volta_data": None,
                    "field_diffs": [],
                }
            )

    for bn, imported in sync_by_bn.items():
        if is_cancelled(imported.opzegdatum):
            continue

        # Check if a decision already exists
        decision = decisions.get(bn)

        # Rule 1: already linked live user
        if bn in user_bn_map:
            uid = user_bn_map[bn]
            user = users_by_id.get(uid)
            if user is not None and user.email not in system_emails:
                current = get_volta(store, VOLTA_DATA_TABLE, bn)
                diffs = compute_live_user_field_diffs(user, current, imported)
                live_users_enriched.append(
                    {
                        "bondsnummer": bn,
                        "user": serialize_admin_user(
                            make_admin_user_record(user, bn, current)
                        ),
                        "current_volta_data": volta_to_dict(current)
                        if current
                        else None,
                        "incoming_volta_data": volta_to_dict(imported),
                        "field_diffs": serialize_field_diffs(diffs),
                    }
                )
            continue

        # Rule 2: already linked registration
        if bn in reg_bn_map:
            reg = reg_bn_map[bn]
            current = get_volta(store, VOLTA_DATA_TABLE, bn)
            diffs = compute_field_diffs(current, imported)
            email_will_change = normalize_email(imported.email) != normalize_email(
                reg.email
            )
            pending_registrations_updated.append(
                {
                    "bondsnummer": bn,
                    "registration": serialize_admin_registration(
                        make_admin_registration_record(reg, current)
                    ),
                    "current_volta_data": volta_to_dict(current) if current else None,
                    "incoming_volta_data": volta_to_dict(imported),
                    "field_diffs": serialize_field_diffs(diffs),
                    "email_will_change": email_will_change,
                }
            )
            continue

        # Has a decision been recorded?
        if decision is not None:
            if decision.kind == "registration" and decision.subject_id:
                reg = get_registration(store, decision.subject_id)
                if reg is not None:
                    current = get_volta(store, VOLTA_DATA_TABLE, bn)
                    diffs = compute_field_diffs(current, imported)
                    email_will_change = normalize_email(
                        imported.email
                    ) != normalize_email(reg.email)
                    registrations_accepted.append(
                        {
                            "bondsnummer": bn,
                            "registration": serialize_admin_registration(
                                make_admin_registration_record(reg, current)
                            ),
                            "current_volta_data": (
                                volta_to_dict(current) if current else None
                            ),
                            "incoming_volta_data": volta_to_dict(imported),
                            "field_diffs": serialize_field_diffs(diffs),
                            "email_will_change": email_will_change,
                        }
                    )
                    continue
            elif decision.kind == "user" and decision.subject_id:
                user = users_by_id.get(decision.subject_id)
                if user is not None:
                    current = get_volta(store, VOLTA_DATA_TABLE, bn)
                    diffs = compute_live_user_field_diffs(user, current, imported)
                    live_users_enriched.append(
                        {
                            "bondsnummer": bn,
                            "user": serialize_admin_user(
                                make_admin_user_record(user, bn, current)
                            ),
                            "current_volta_data": (
                                volta_to_dict(current) if current else None
                            ),
                            "incoming_volta_data": volta_to_dict(imported),
                            "field_diffs": serialize_field_diffs(diffs),
                        }
                    )
                    continue
            elif decision.kind == "none":
                lastname = build_lastname_from_volta(imported)
                registrations_created.append(
                    {
                        "bondsnummer": bn,
                        "email": normalize_email(imported.email),
                        "firstname": imported.voornaam,
                        "lastname": lastname,
                        "incoming_volta_data": volta_to_dict(imported),
                    }
                )
                continue

        # Rule 3: unresolved -> review required
        candidates = generate_candidates(imported, unlinked_regs, unlinked_users)
        review_required.append(
            {
                "bondsnummer": bn,
                "incoming_volta_data": volta_to_dict(imported),
                "candidates": [
                    {
                        "kind": c.kind,
                        "subject_id": c.subject_id,
                        "email": c.email,
                        "display_name": c.display_name,
                        "reasons": c.reasons,
                    }
                    for c in candidates
                ],
            }
        )

    # Departed: linked live users not in import or cancelled
    for uid, bn in user_to_bn.items():
        user = users_by_id.get(uid)
        if user is None or user.email in system_emails:
            continue
        if bn not in sync_by_bn or is_cancelled(sync_by_bn[bn].opzegdatum):
            volta = get_volta(store, VOLTA_DATA_TABLE, bn)
            departed_users.append(
                serialize_admin_user(make_admin_user_record(user, bn, volta))
            )

    can_complete = len(review_required) == 0

    return SyncStatus(
        sync_in_progress=True,
        sync_state_counter=state.counter,
        file_modified_at=state.file_modified_at,
        can_complete=can_complete,
        review_required=review_required,
        registrations_created=registrations_created,
        registrations_accepted=registrations_accepted,
        pending_registrations_updated=pending_registrations_updated,
        live_users_enriched=live_users_enriched,
        departed_users=departed_users,
        volta_data_changes=volta_data_changes,
    )


def serialize_sync_status(status: SyncStatus) -> dict:
    return {
        "sync_in_progress": status.sync_in_progress,
        "sync_state_counter": status.sync_state_counter,
        "file_modified_at": status.file_modified_at,
        "can_complete": status.can_complete,
        "review_required": status.review_required,
        "registrations_created": status.registrations_created,
        "registrations_accepted": status.registrations_accepted,
        "pending_registrations_updated": status.pending_registrations_updated,
        "live_users_enriched": status.live_users_enriched,
        "departed_users": status.departed_users,
        "volta_data_changes": status.volta_data_changes,
    }


# ---------------------------------------------------------------------------
# Resolve sync match (recording step only)
# ---------------------------------------------------------------------------


@dataclass
class ResolveSyncMatchResult:
    success: bool
    message: str


def validate_resolve_target(
    store: Storage, bondsnummer: int, kind: str, subject_id: str | None
) -> ResolveSyncMatchResult | None:
    """Validate the chosen target exists and has no conflicting link.

    Returns an error result if invalid, None if valid.
    """
    if kind == "registration":
        if subject_id is None:
            return ResolveSyncMatchResult(success=False, message="Missing subject_id")
        reg = get_registration(store, subject_id)
        if reg is None:
            return ResolveSyncMatchResult(
                success=False,
                message=f"Registration {subject_id} not found",
            )
        if reg.bondsnummer is not None and reg.bondsnummer != bondsnummer:
            return ResolveSyncMatchResult(
                success=False,
                message=(
                    f"Registration already linked to bondsnummer {reg.bondsnummer}"
                ),
            )
    elif kind == "user":
        if subject_id is None:
            return ResolveSyncMatchResult(success=False, message="Missing subject_id")
        email_result = store.get("users", f"{subject_id}:email")
        if email_result is None:
            return ResolveSyncMatchResult(
                success=False,
                message=f"User {subject_id} not found",
            )
        current_bn = get_bondsnummer_by_user_id(store, subject_id)
        if current_bn is not None and current_bn != bondsnummer:
            return ResolveSyncMatchResult(
                success=False,
                message=(
                    f"User {subject_id} already linked to bondsnummer {current_bn}"
                ),
            )
    elif kind != "none":
        return ResolveSyncMatchResult(success=False, message=f"Unknown kind: {kind}")
    return None


def resolve_sync_match(
    store: Storage,
    bondsnummer: int,
    kind: str,
    subject_id: str | None,
    sync_state_counter: int | None = None,
) -> ResolveSyncMatchResult:
    """Record one pending decision in sync_decisions.

    When sync_state_counter is provided, the write uses try_update
    to atomically verify the counter and advance it.
    """
    state = get_sync_state(store)
    if not state.in_progress:
        return ResolveSyncMatchResult(success=False, message="No pending sync session")

    imported = get_volta(store, SYNC_TABLE, bondsnummer)
    if imported is None:
        return ResolveSyncMatchResult(
            success=False,
            message=f"Bondsnummer {bondsnummer} not in current import",
        )

    target_error = validate_resolve_target(store, bondsnummer, kind, subject_id)
    if target_error is not None:
        return target_error

    store_decision(
        store,
        bondsnummer,
        SyncDecision(kind=kind, subject_id=subject_id),
    )

    # Advance counter: update() raises UpdateCounterMismatch on
    # conflict, rolling back the decision write above.
    if sync_state_counter is not None:
        advance_sync_state(store, sync_state_counter, True)
    else:
        set_sync_state(store, True)

    return ResolveSyncMatchResult(
        success=True,
        message=f"Recorded {kind} decision for bondsnummer {bondsnummer}",
    )


# ---------------------------------------------------------------------------
# Link bondsnummer (explicit admin operation, outside sync session)
# ---------------------------------------------------------------------------


def link_bondsnummer(
    store: Storage,
    kind: str,
    subject_id: str,
    bondsnummer: int,
) -> ResolveSyncMatchResult:
    if kind == "registration":
        reg = get_registration(store, subject_id)
        if reg is None:
            return ResolveSyncMatchResult(
                success=False,
                message=f"Registration {subject_id} not found",
            )
        if reg.bondsnummer is not None and reg.bondsnummer != bondsnummer:
            return ResolveSyncMatchResult(
                success=False,
                message=(
                    f"Registration already linked to bondsnummer {reg.bondsnummer}"
                ),
            )
        existing = get_registration_by_bondsnummer(store, bondsnummer)
        if existing is not None and existing.registration_id != subject_id:
            return ResolveSyncMatchResult(
                success=False,
                message=(
                    f"Bondsnummer {bondsnummer} already linked "
                    f"to registration {existing.registration_id}"
                ),
            )
        existing_user = get_user_id_by_bondsnummer(store, bondsnummer)
        if existing_user is not None:
            return ResolveSyncMatchResult(
                success=False,
                message=(
                    f"Bondsnummer {bondsnummer} already linked to user {existing_user}"
                ),
            )
        reg.bondsnummer = bondsnummer
        reg.accepted = True
        upsert_registration(store, reg)
        return ResolveSyncMatchResult(
            success=True,
            message=f"Linked registration {subject_id} to bondsnummer {bondsnummer}",
        )

    if kind == "user":
        email_result = store.get("users", f"{subject_id}:email")
        if email_result is None:
            return ResolveSyncMatchResult(
                success=False, message=f"User {subject_id} not found"
            )
        current_bn = get_bondsnummer_by_user_id(store, subject_id)
        if current_bn is not None and current_bn != bondsnummer:
            return ResolveSyncMatchResult(
                success=False,
                message=(
                    f"User {subject_id} already linked to bondsnummer {current_bn}"
                ),
            )
        existing_user = get_user_id_by_bondsnummer(store, bondsnummer)
        if existing_user is not None and existing_user != subject_id:
            return ResolveSyncMatchResult(
                success=False,
                message=(
                    f"Bondsnummer {bondsnummer} already linked to user {existing_user}"
                ),
            )
        existing_reg = get_registration_by_bondsnummer(store, bondsnummer)
        if existing_reg is not None:
            return ResolveSyncMatchResult(
                success=False,
                message=(
                    f"Bondsnummer {bondsnummer} already linked "
                    f"to registration {existing_reg.registration_id}"
                ),
            )
        set_user_bondsnummer(store, bondsnummer, subject_id)
        return ResolveSyncMatchResult(
            success=True,
            message=f"Linked user {subject_id} to bondsnummer {bondsnummer}",
        )

    return ResolveSyncMatchResult(success=False, message=f"Unknown kind: {kind}")


# ---------------------------------------------------------------------------
# Complete sync
# ---------------------------------------------------------------------------


def sync_user_profile(store: Storage, user_id: str, row: VoltaRow) -> None:
    profile_result = store.get("users", f"{user_id}:profile")
    if profile_result is None:
        return
    _, counter = profile_result
    lastname = build_lastname_from_volta(row)
    profile_data = {"firstname": row.voornaam, "lastname": lastname}
    profile_bytes = json.dumps(profile_data).encode("utf-8")
    store.update("users", f"{user_id}:profile", profile_bytes, counter, expires_at=0)


def refresh_birthdays_projection(store: Storage) -> None:
    """Rebuild birthdays from applied Volta data for linked live users."""
    birthdays = []
    for key in store.list_keys(BONDSNUMMER_TABLE):
        result = store.get(BONDSNUMMER_TABLE, key)
        if result is None:
            continue
        user_id = result[0].decode("utf-8")
        row = get_volta(store, VOLTA_DATA_TABLE, int(key))
        if row is None:
            continue
        birthdays.append(
            {
                "user_id": user_id,
                "geboortedatum": row.geboortedatum,
                "voornaam": row.voornaam,
                "tussenvoegsel": row.tussenvoegsel,
                "achternaam": row.achternaam,
            }
        )
    replace_birthdays(store, birthdays)


def create_invite_outbox_row(
    store: Storage,
    registration_id: str,
    email: str,
    display_name: str,
    now: int | None = None,
) -> None:
    create_outbox_row(
        store,
        kind="send_registration_invite",
        subject_kind="registration",
        subject_id=registration_id,
        payload={
            "registration_id": registration_id,
            "email": email,
            "display_name": display_name,
        },
        now=now,
    )


@dataclass
class CompleteSyncResult:
    success: bool
    message: str
    volta_rows_applied: int
    registrations_created: int
    registrations_accepted: int
    registrations_updated: int
    users_refreshed: int
    users_departed: int


@dataclass
class CompleteSyncError:
    message: str


def build_bondsnummer_maps(
    store: Storage,
) -> tuple[dict[int, str], dict[str, int]]:
    """Build bondsnummer -> user_id and user_id -> bondsnummer maps."""
    user_bn_map: dict[int, str] = {}
    user_to_bn: dict[str, int] = {}
    for key in store.list_keys(BONDSNUMMER_TABLE):
        result = store.get(BONDSNUMMER_TABLE, key)
        if result is not None:
            bn = int(key)
            uid = result[0].decode("utf-8")
            user_bn_map[bn] = uid
            user_to_bn[uid] = bn
    return user_bn_map, user_to_bn


def build_registration_bondsnummer_map(
    store: Storage,
) -> dict[int, Registration]:
    reg_bn_map: dict[int, Registration] = {}
    for reg in list_registrations(store):
        if reg.bondsnummer is not None:
            reg_bn_map[reg.bondsnummer] = reg
    return reg_bn_map


def check_all_resolved(
    sync_by_bn: dict[int, VoltaRow],
    user_bn_map: dict[int, str],
    reg_bn_map: dict[int, Registration],
    decisions: dict[int, SyncDecision],
) -> CompleteSyncError | None:
    """Return error if any imported row is unresolved."""
    for bn, row in sync_by_bn.items():
        if is_cancelled(row.opzegdatum):
            continue
        if bn in user_bn_map or bn in reg_bn_map:
            continue
        if bn not in decisions:
            return CompleteSyncError(message=f"Unresolved bondsnummer {bn}")
    return None


def apply_decisions(
    store: Storage,
    decisions: dict[int, SyncDecision],
    sync_by_bn: dict[int, VoltaRow],
    now: int,
) -> tuple[int, int]:
    """Apply pending sync decisions. Returns (created, accepted)."""
    created = 0
    accepted = 0
    for bn, decision in decisions.items():
        imported = sync_by_bn.get(bn)
        if imported is None:
            continue

        if decision.kind == "registration" and decision.subject_id:
            reg = get_registration(store, decision.subject_id)
            if reg is None:
                continue
            reg.bondsnummer = bn
            reg.accepted = True
            upsert_registration(store, reg)
            new_email = normalize_email(imported.email)
            if normalize_email(reg.email) != new_email:
                migrate_registration_email(store, reg.registration_id, new_email)
                reg = get_registration(store, reg.registration_id)
                if reg is None:
                    continue
            create_invite_outbox_row(
                store,
                reg.registration_id,
                reg.email,
                imported.voornaam,
                now,
            )
            accepted += 1

        elif decision.kind == "user" and decision.subject_id:
            set_user_bondsnummer(store, bn, decision.subject_id)

        elif decision.kind == "none":
            email = normalize_email(imported.email)
            lastname = build_lastname_from_volta(imported)
            reg = create_or_reuse_registration(
                store, email, imported.voornaam, lastname, accepted=True
            )
            reg.bondsnummer = bn
            reg.accepted = True
            upsert_registration(store, reg)
            create_invite_outbox_row(
                store,
                reg.registration_id,
                reg.email,
                imported.voornaam,
                now,
            )
            created += 1

    return created, accepted


def apply_linked_registration_updates(
    store: Storage,
    reg_bn_map: dict[int, Registration],
    sync_by_bn: dict[int, VoltaRow],
    decisions: dict[int, SyncDecision],
    now: int,
) -> int:
    """Rewrite emails for already-linked registrations. Returns count."""
    updated = 0
    for bn, reg in reg_bn_map.items():
        imported = sync_by_bn.get(bn)
        if imported is None:
            continue
        if bn in decisions:
            continue
        new_email = normalize_email(imported.email)
        old_email = normalize_email(reg.email)
        if new_email != old_email:
            migrate_registration_email(store, reg.registration_id, new_email)
            create_invite_outbox_row(
                store,
                reg.registration_id,
                new_email,
                imported.voornaam,
                now,
            )
            updated += 1
    return updated


def refresh_linked_live_users(
    store: Storage,
    sync_by_bn: dict[int, VoltaRow],
    system_emails: set[str],
    timestamp: int,
) -> int:
    """Refresh profile data and renew member for linked live users."""
    refreshed = 0
    for key in store.list_keys(BONDSNUMMER_TABLE):
        bn = int(key)
        result = store.get(BONDSNUMMER_TABLE, key)
        if result is None:
            continue
        user_id = result[0].decode("utf-8")
        imported = sync_by_bn.get(bn)
        if imported is None or is_cancelled(imported.opzegdatum):
            continue
        email_result = store.get("users", f"{user_id}:email")
        if email_result is None:
            continue
        if email_result[0].decode("utf-8") in system_emails:
            continue
        sync_user_profile(store, user_id, imported)
        add_permission(store, timestamp, user_id, Permissions.MEMBER)
        refreshed += 1
    return refreshed


def remove_departed_users(
    store: Storage,
    sync_by_bn: dict[int, VoltaRow],
    system_emails: set[str],
) -> int:
    """Remove departed linked live users. Returns count."""
    departed_keys = []
    for key in store.list_keys(BONDSNUMMER_TABLE):
        bn = int(key)
        result = store.get(BONDSNUMMER_TABLE, key)
        if result is None:
            continue
        user_id = result[0].decode("utf-8")
        email_result = store.get("users", f"{user_id}:email")
        if email_result is None:
            continue
        if email_result[0].decode("utf-8") in system_emails:
            continue
        if bn not in sync_by_bn or is_cancelled(sync_by_bn[bn].opzegdatum):
            departed_keys.append((user_id, bn))

    for user_id, bn in departed_keys:
        email_result = store.get("users", f"{user_id}:email")
        if email_result is None:
            continue
        email = email_result[0].decode("utf-8")
        store.delete("users", f"{user_id}:profile")
        store.delete("users", f"{user_id}:email")
        store.delete("users", f"{user_id}:password")
        store.delete("users", f"{user_id}:disabled")
        store.delete("users", f"{user_id}:sessions_counter")
        store.delete("users_by_email", email)
        remove_permission(store, user_id, "member")
        delete_user_bondsnummer(store, bn)

    return len(departed_keys)


def complete_sync(
    store: Storage,
    sync_state_counter: int | None = None,
) -> CompleteSyncResult | CompleteSyncError:
    """Apply the pending sync session in one atomic callback.

    Composed from storage-only helpers; no external side effects.
    """
    state = get_sync_state(store)
    if not state.in_progress:
        return CompleteSyncError(message="No pending sync session")

    # Raises UpdateCounterMismatch on stale counter, rolling back.
    if sync_state_counter is not None:
        advance_sync_state(store, sync_state_counter, True)

    now = int(time_mod.time())
    sync_entries = list_volta(store, SYNC_TABLE)
    sync_by_bn = {e.bondsnummer: e for e in sync_entries}
    decisions = list_decisions(store)
    system_emails = set(store.list_keys(SYSTEM_USERS_TABLE))

    user_bn_map, _ = build_bondsnummer_maps(store)
    reg_bn_map = build_registration_bondsnummer_map(store)

    unresolved = check_all_resolved(sync_by_bn, user_bn_map, reg_bn_map, decisions)
    if unresolved is not None:
        return unresolved

    # Step 1: Replace volta_data
    store.clear(VOLTA_DATA_TABLE)
    for entry in sync_entries:
        upsert_volta(store, VOLTA_DATA_TABLE, entry)

    # Step 2: Apply decisions
    regs_created, regs_accepted = apply_decisions(store, decisions, sync_by_bn, now)

    # Rebuild maps after decisions
    reg_bn_map = build_registration_bondsnummer_map(store)

    # Step 3: Update linked registrations + refresh live users
    regs_updated = apply_linked_registration_updates(
        store, reg_bn_map, sync_by_bn, decisions, now
    )
    users_refreshed = refresh_linked_live_users(store, sync_by_bn, system_emails, now)

    # Step 4: Remove departed
    users_departed = remove_departed_users(store, sync_by_bn, system_emails)

    # Step 5: Rebuild derived tables
    refresh_birthdays_projection(store)

    # Clear sync session
    store.clear(SYNC_TABLE)
    store.clear(SYNC_DECISIONS_TABLE)
    set_sync_state(store, False)

    return CompleteSyncResult(
        success=True,
        message="Sync completed",
        volta_rows_applied=len(sync_entries),
        registrations_created=regs_created,
        registrations_accepted=regs_accepted,
        registrations_updated=regs_updated,
        users_refreshed=users_refreshed,
        users_departed=users_departed,
    )
