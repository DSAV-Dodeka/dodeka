"""Integration tests for sync operations.

Tests run sequentially within the class, building on each other's state.
The admin user (root_admin@localhost) is bootstrapped at server startup
and auto-marked as a system user (excluded from sync comparison).

Member permission lifecycle:
  1. Signup grants member permission automatically (1-year TTL).
  2. update_existing renews the permission each sync cycle.
  3. remove_departed fully deletes the user account and all data.
"""

import csv
import io
import pathlib
from datetime import date
from typing import Any, Callable

from tiauth_faroe.client import ActionErrorResult

from apiserver.data.client import AuthClient
from apiserver.sync import is_cancelled, parse_csv

Command = Callable[..., Any]

# Column names matching the Atletiekunie member export format
AU_COLUMNS = [
    "Verenigingscode",
    "Regio",
    "Naam vereniging",
    "Clubnummer",
    "Bondsnummer",
    "Club lidmaatschap type",
    "Club lidmaatschap startdatum",
    "Club lidmaatschap einddatum",
    "Club lidmaatschap opzegdatum",
    "Club lidmaatschap opzegreden",
    "Bond lidmaatschapstype",
    "Bond lidmaatschap startdatum",
    "Bond lidmaatschap einddatum",
    "Bond lidmaatschap opzegdatum",
    "Bond opzegreden",
    "Voornaam",
    "Tussenvoegsel",
    "Achternaam",
    "Initialen",
    "Geslacht",
    "Geboortedatum",
    "Nationaliteit",
    "Straat",
    "Huisnummer",
    "Huisnummer toevoeging",
    "Postcode",
    "Stad",
    "Landcode",
    "Mobiel",
    "Telefoon",
    "Email",
    "Naam ouder 1",
    "Email ouder 1",
    "Telefoon ouder 1",
    "Naam ouder 2",
    "Email ouder 2",
    "Telefoon ouder 2",
    "Incasso",
    "Naam bankrekening",
    "IBAN",
    "BIC",
    "Mandaat ID",
    "Mandaat datum",
    "Contributie termijn",
    "VOG",
    "_Geef je toestemming om foto's van jou op onze social media te plaatsen?",
    "_Ben je student?",
]


def make_au_csv(members: list[dict[str, str]]) -> str:
    """Create CSV content in Atletiekunie export format (without BOM)."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=AU_COLUMNS, restval="")
    writer.writeheader()
    for member in members:
        writer.writerow(member)
    return buf.getvalue()


MEMBERS = [
    {
        "Bondsnummer": "1001",
        "Voornaam": "Alice",
        "Achternaam": "Smith",
        "Geslacht": "V",
        "Geboortedatum": "15/01/1990",
        "Email": "alice@example.com",
    },
    {
        "Bondsnummer": "1002",
        "Voornaam": "Bob",
        "Tussenvoegsel": "de",
        "Achternaam": "Vries",
        "Geslacht": "M",
        "Geboortedatum": "20/06/1992",
        "Email": "bob@example.com",
    },
    {
        "Bondsnummer": "1003",
        "Voornaam": "Charlie",
        "Achternaam": "Brown",
        "Geslacht": "M",
        "Geboortedatum": "03/11/1988",
        "Email": "charlie@example.com",
    },
]

CANCELLED_MEMBER = {
    "Bondsnummer": "1004",
    "Voornaam": "Diana",
    "Achternaam": "Prince",
    "Geslacht": "V",
    "Geboortedatum": "10/03/1985",
    "Email": "diana@example.com",
    "Club lidmaatschap opzegdatum": "15/06/2024",
    "Club lidmaatschap opzegreden": "Eigen verzoek",
}


def test_parse_csv(tmp_path: pathlib.Path) -> None:
    """Parse CSV in Atletiekunie export format (BOM, 47 columns)."""
    csv_content = make_au_csv(MEMBERS)
    csv_file = tmp_path / "export.csv"
    # Write with UTF-8 BOM like real exports
    csv_file.write_text(csv_content, encoding="utf-8-sig")

    with open(csv_file) as f:
        content = f.read()

    entries = parse_csv(content)
    assert len(entries) == 3
    assert entries[0].email == "alice@example.com"
    assert entries[0].bondsnummer == 1001
    assert entries[0].voornaam == "Alice"
    assert entries[0].achternaam == "Smith"
    assert entries[0].opzegdatum == ""
    assert entries[1].tussenvoegsel == "de"
    assert entries[2].email == "charlie@example.com"


def test_parse_csv_with_cancellation() -> None:
    """Parse CSV with cancelled member reads opzegdatum."""
    csv_content = make_au_csv([*MEMBERS, CANCELLED_MEMBER])
    entries = parse_csv(csv_content)
    assert len(entries) == 4
    cancelled = [e for e in entries if e.opzegdatum]
    assert len(cancelled) == 1
    assert cancelled[0].email == "diana@example.com"
    assert cancelled[0].opzegdatum == "15/06/2024"


def test_is_cancelled() -> None:
    """Unit test for is_cancelled date checking.

    Spec: A future cancellation date is ignored until that date has passed.
    Cancelled means opzegdatum <= today.
    """
    # Empty string -> not cancelled
    assert is_cancelled("") is False
    # Past date -> cancelled
    assert is_cancelled("01/01/2020", today=date(2025, 1, 1)) is True
    # Future date -> not cancelled
    assert is_cancelled("01/01/2030", today=date(2025, 1, 1)) is False
    # Today's date -> cancelled (boundary: <=)
    assert is_cancelled("15/06/2025", today=date(2025, 6, 15)) is True
    # Yesterday -> cancelled
    assert is_cancelled("14/06/2025", today=date(2025, 6, 15)) is True
    # Tomorrow -> not cancelled
    assert is_cancelled("16/06/2025", today=date(2025, 6, 15)) is False
    # Invalid format -> not cancelled
    assert is_cancelled("not-a-date") is False
    # Wrong date format (YYYY-MM-DD) -> not cancelled
    assert is_cancelled("2025-01-01") is False


class TestSync:
    """Integration tests for sync operations."""

    def test_import_csv(self, command: Command) -> None:
        """Import CSV content into sync table."""
        csv_content = make_au_csv(MEMBERS)
        result = command("import_sync", csv_content=csv_content)
        assert result["imported"] == 3

    def test_compute_groups_admin_excluded(self, command: Command) -> None:
        """System user root_admin doesn't appear in departed, 3 new members."""
        result = command("compute_groups")
        assert "root_admin@localhost" not in result["departed"]
        assert len(result["departed"]) == 0
        assert len(result["to_accept"]) == 3

    def test_accept_new(self, command: Command) -> None:
        """Accept all new users as board-approved."""
        result = command("accept_new")
        assert result["added"] == 3

    def test_compute_groups_after_accept(self, command: Command) -> None:
        """Accepted users move to pending (in newusers, not yet registered)."""
        result = command("compute_groups")
        assert len(result["to_accept"]) == 0
        assert len(result["pending_signup"]) == 3

    def test_create_accounts(self, command: Command) -> None:
        """Complete signup for all accepted users (creates real user accounts)."""
        result = command("create_accounts", password="Str0ng_T3st_P@ss!2024")
        assert result["created"] == 3
        assert result["failed"] == 0

    def test_compute_groups_after_registration(self, command: Command) -> None:
        """After registration, members show as existing (not new/pending)."""
        result = command("compute_groups")
        assert len(result["to_accept"]) == 0
        assert len(result["pending_signup"]) == 0
        existing_emails = {e["sync"]["email"] for e in result["existing"]}
        assert "alice@example.com" in existing_emails
        assert "bob@example.com" in existing_emails
        assert "charlie@example.com" in existing_emails

    def test_existing_current_null_before_update(self, command: Command) -> None:
        """Before update_existing, existing pairs have null current userdata.

        Spec: update_existing is the only path that populates userdata.
        Creating an account alone does not populate these tables.
        """
        result = command("compute_groups")
        for pair in result["existing"]:
            assert pair["current"] is None, (
                f"Expected null current for {pair['sync']['email']} "
                "before update_existing"
            )

    def test_signup_grants_member_permission(self, command: Command) -> None:
        """Signup automatically grants member permission (no update_existing needed)."""
        # Temporarily clear sync to check departed status — only users
        # with member permission appear as departed
        command("import_sync", csv_content=make_au_csv([]))
        groups = command("compute_groups")
        departed = set(groups["departed"])
        assert "alice@example.com" in departed
        assert "bob@example.com" in departed
        assert "charlie@example.com" in departed

        # Restore sync for subsequent tests
        command("import_sync", csv_content=make_au_csv(MEMBERS))

    def test_update_existing_syncs_data(self, command: Command) -> None:
        """update_existing copies sync data to userdata and renews permission."""
        result = command("update_existing")
        assert result["updated"] == 3

        # Verify departed detection still works after update_existing
        csv_content = make_au_csv([MEMBERS[0]])  # only alice
        command("import_sync", csv_content=csv_content)

        groups = command("compute_groups")
        departed = set(groups["departed"])
        assert "bob@example.com" in departed
        assert "charlie@example.com" in departed
        assert "alice@example.com" not in departed

    def test_cancelled_member_is_departed(self, command: Command) -> None:
        """Member with opzegdatum in CSV is treated as departed."""
        cancelled_alice = {
            **MEMBERS[0],
            "Club lidmaatschap opzegdatum": "01/12/2024",
            "Club lidmaatschap opzegreden": "Eigen verzoek",
        }
        csv_content = make_au_csv(
            [
                cancelled_alice,
                MEMBERS[1],
                MEMBERS[2],
            ]
        )
        command("import_sync", csv_content=csv_content)

        groups = command("compute_groups")
        departed = set(groups["departed"])
        # alice is cancelled -> departed
        assert "alice@example.com" in departed
        # bob and charlie are active -> existing
        existing_emails = {e["sync"]["email"] for e in groups["existing"]}
        assert "bob@example.com" in existing_emails
        assert "charlie@example.com" in existing_emails

    def test_future_opzegdatum_not_departed(self, command: Command) -> None:
        """Member with future opzegdatum is treated as active, not departed.

        Spec: A future cancellation date is ignored until that date has passed.
        """
        future_alice = {
            **MEMBERS[0],
            "Club lidmaatschap opzegdatum": "01/01/2099",
        }
        csv_content = make_au_csv([future_alice, MEMBERS[1], MEMBERS[2]])
        command("import_sync", csv_content=csv_content)

        groups = command("compute_groups")
        # Future opzegdatum: alice is active, not departed
        assert "alice@example.com" not in groups["departed"]
        existing_emails = {e["sync"]["email"] for e in groups["existing"]}
        assert "alice@example.com" in existing_emails

        # Restore state: alice with past opzegdatum for subsequent tests
        cancelled_alice = {
            **MEMBERS[0],
            "Club lidmaatschap opzegdatum": "01/12/2024",
            "Club lidmaatschap opzegreden": "Eigen verzoek",
        }
        csv_content = make_au_csv([cancelled_alice, MEMBERS[1], MEMBERS[2]])
        command("import_sync", csv_content=csv_content)

    def test_remove_departed_cancelled(self, command: Command) -> None:
        """Remove departed (cancelled) member revokes their permission."""
        result = command("remove_departed", email="alice@example.com")
        assert result["removed"] == 1

        groups = command("compute_groups")
        assert "alice@example.com" not in groups["departed"]

    def test_restore_and_renew(self, command: Command) -> None:
        """Re-import all active, update_existing renews permissions.

        Alice was fully deleted in test_remove_departed_cancelled, so she
        appears as to_accept. Only bob and charlie are existing initially.
        """
        csv_content = make_au_csv(MEMBERS)
        command("import_sync", csv_content=csv_content)

        result = command("update_existing")
        assert result["updated"] == 2  # Only bob and charlie

        # Re-create alice: accept + signup + sync
        command("accept_new", email="alice@example.com")
        command("create_accounts", password="Str0ng_T3st_P@ss!2024")
        command("update_existing")

        # Verify all 3 have member permission
        command("import_sync", csv_content=make_au_csv([]))
        groups = command("compute_groups")
        departed = set(groups["departed"])
        assert "alice@example.com" in departed
        assert "bob@example.com" in departed
        assert "charlie@example.com" in departed

    def test_remove_departed_deletes_user(
        self, command: Command, auth_client: AuthClient
    ) -> None:
        """remove_departed fully deletes the user account."""
        # Restore all members first
        command("import_sync", csv_content=make_au_csv(MEMBERS))
        command("update_existing")

        # Remove bob (only bob absent from CSV)
        command("import_sync", csv_content=make_au_csv([MEMBERS[0], MEMBERS[2]]))
        command("remove_departed", email="bob@example.com")

        # Signin should fail with user_not_found (fully deleted)
        result = auth_client.create_signin("bob@example.com")
        assert isinstance(result, ActionErrorResult)
        assert result.error_code == "user_not_found"

    def test_birthdays_populated(self, command: Command) -> None:
        """update_existing populates birthdays table with member data."""
        # Bob was fully deleted in test_remove_departed_deletes_user.
        # Re-create bob: accept + signup + sync
        command("import_sync", csv_content=make_au_csv(MEMBERS))
        command("accept_new", email="bob@example.com")
        command("create_accounts", password="Str0ng_T3st_P@ss!2024")
        command("update_existing")

        birthdays = command("list_birthdays")
        assert len(birthdays) == 3

        # Check that each member's birthday data is present
        by_name = {b["voornaam"]: b for b in birthdays}
        assert "Alice" in by_name
        assert by_name["Alice"]["geboortedatum"] == "15/01/1990"
        assert by_name["Alice"]["achternaam"] == "Smith"
        assert by_name["Bob"]["geboortedatum"] == "20/06/1992"
        assert by_name["Bob"]["tussenvoegsel"] == "de"
        assert by_name["Charlie"]["geboortedatum"] == "03/11/1988"

    def test_birthdays_removed_on_departure(self, command: Command) -> None:
        """remove_departed deletes birthday entry for departed member."""
        # Remove alice from sync
        command("import_sync", csv_content=make_au_csv([MEMBERS[1], MEMBERS[2]]))
        command("remove_departed", email="alice@example.com")

        birthdays = command("list_birthdays")
        names = {b["voornaam"] for b in birthdays}
        assert "Alice" not in names
        assert "Bob" in names
        assert "Charlie" in names

        # Restore alice for subsequent tests (fully deleted, needs full flow)
        command("import_sync", csv_content=make_au_csv(MEMBERS))
        command("accept_new", email="alice@example.com")
        command("create_accounts", password="Str0ng_T3st_P@ss!2024")
        command("update_existing")

    def test_bondsnummer_email_change(
        self, command: Command, auth_client: AuthClient
    ) -> None:
        """Bondsnummer match detects email change and update_existing applies it.

        When a member changes their email in the athletics union system, the
        CSV has the same bondsnummer but a new email address. The system should:
        1. Detect the email mismatch in compute_groups (not mark as departed+new)
        2. Apply the email change in update_existing
        3. Allow signin with the new email
        """
        # Start from clean state: all members imported and synced
        command("import_sync", csv_content=make_au_csv(MEMBERS))
        command("update_existing")

        # Re-import with alice having a new email but same bondsnummer
        alice_new_email = {
            **MEMBERS[0],
            "Email": "alice.new@example.com",
        }
        csv_content = make_au_csv([alice_new_email, MEMBERS[1], MEMBERS[2]])
        command("import_sync", csv_content=csv_content)

        # compute_groups should detect the email change
        groups = command("compute_groups")

        # alice should NOT be in new (she matched by bondsnummer)
        new_emails = {e["email"] for e in groups["to_accept"]}
        assert "alice.new@example.com" not in new_emails

        # alice's old email should NOT be in departed
        assert "alice@example.com" not in groups["departed"]

        # Email change should be reported
        assert len(groups["email_changes"]) == 1
        change = groups["email_changes"][0]
        assert change["old_email"] == "alice@example.com"
        assert change["new_email"] == "alice.new@example.com"
        assert change["bondsnummer"] == 1001

        # alice should be in existing (matched by bondsnummer)
        existing_sync_emails = {e["sync"]["email"] for e in groups["existing"]}
        assert "alice.new@example.com" in existing_sync_emails

        # Apply changes via update_existing
        result = command("update_existing")
        assert result["email_changes_applied"] == 1

        # Signin with new email should work
        signin = auth_client.create_signin("alice.new@example.com")
        assert not isinstance(signin, ActionErrorResult)

        # Signin with old email should fail (user not found)
        signin = auth_client.create_signin("alice@example.com")
        assert isinstance(signin, ActionErrorResult)

        # Birthday should be updated to new email
        birthdays = command("list_birthdays")
        by_name = {b["voornaam"]: b for b in birthdays}
        assert "Alice" in by_name

        # Subsequent compute_groups should be clean (no email_changes)
        groups = command("compute_groups")
        assert len(groups["email_changes"]) == 0
        existing_emails = {e["sync"]["email"] for e in groups["existing"]}
        assert "alice.new@example.com" in existing_emails

    def test_system_user_in_csv_excluded(self, command: Command) -> None:
        """System user in CSV is excluded from all sync groups.

        Spec: System users are excluded from sync comparison in
        compute_groups -- they never appear in any group.
        """
        admin_member = {
            "Bondsnummer": "9999",
            "Voornaam": "Root",
            "Achternaam": "Admin",
            "Geslacht": "M",
            "Geboortedatum": "01/01/1970",
            "Email": "root_admin@localhost",
        }
        alice_new = {**MEMBERS[0], "Email": "alice.new@example.com"}
        csv_content = make_au_csv([admin_member, alice_new, MEMBERS[1], MEMBERS[2]])
        command("import_sync", csv_content=csv_content)

        groups = command("compute_groups")

        all_new = {e["email"] for e in groups["to_accept"]}
        all_existing = {e["sync"]["email"] for e in groups["existing"]}
        all_pending = set(groups["pending_signup"])
        all_departed = set(groups["departed"])

        assert "root_admin@localhost" not in all_new
        assert "root_admin@localhost" not in all_existing
        assert "root_admin@localhost" not in all_pending
        assert "root_admin@localhost" not in all_departed

    def test_bondsnummer_index_deleted_on_departure(
        self, command: Command, auth_client: AuthClient
    ) -> None:
        """Bondsnummer index is deleted on departure (full deletion).

        With full deletion, all user data including the bondsnummer index
        is removed. A returning member with the same bondsnummer but a new
        email is treated as a completely new member (to_accept).
        """
        # Setup: all 3 active with bondsnummer indexes populated
        alice_new = {**MEMBERS[0], "Email": "alice.new@example.com"}
        csv_content = make_au_csv([alice_new, MEMBERS[1], MEMBERS[2]])
        command("import_sync", csv_content=csv_content)
        command("update_existing")

        # Depart charlie
        csv_content = make_au_csv([alice_new, MEMBERS[1]])
        command("import_sync", csv_content=csv_content)
        command("remove_departed", email="charlie@example.com")

        # Verify charlie is fully deleted (not just disabled)
        signin = auth_client.create_signin("charlie@example.com")
        assert isinstance(signin, ActionErrorResult)
        assert signin.error_code == "user_not_found"

        # Reimport charlie with same bondsnummer (1003) but new email
        charlie_new = {**MEMBERS[2], "Email": "charlie.new@example.com"}
        csv_content = make_au_csv([alice_new, MEMBERS[1], charlie_new])
        command("import_sync", csv_content=csv_content)

        groups = command("compute_groups")

        # Bondsnummer index was deleted: no email change detected
        assert len(groups["email_changes"]) == 0

        # charlie.new is a new member (to_accept), not matched by bondsnummer
        new_emails = {e["email"] for e in groups["to_accept"]}
        assert "charlie.new@example.com" in new_emails

    def test_full_rejoining_after_departure(
        self, command: Command, auth_client: AuthClient
    ) -> None:
        """Departed member returns as new member (full deletion).

        With full deletion, a returning member must go through the full
        accept + signup flow again. They are treated as a completely new
        member.
        """
        # Setup: ensure all 3 active (charlie.new was to_accept from prev test)
        alice_new = {**MEMBERS[0], "Email": "alice.new@example.com"}
        csv_content = make_au_csv([alice_new, MEMBERS[1], MEMBERS[2]])
        command("import_sync", csv_content=csv_content)
        command("accept_new")  # accepts charlie (new) if needed
        command("create_accounts", password="Str0ng_T3st_P@ss!2024")
        command("update_existing")

        # Depart bob
        csv_content = make_au_csv([alice_new, MEMBERS[2]])
        command("import_sync", csv_content=csv_content)
        command("remove_departed", email="bob@example.com")

        # Verify bob is fully deleted
        signin = auth_client.create_signin("bob@example.com")
        assert isinstance(signin, ActionErrorResult)
        assert signin.error_code == "user_not_found"

        birthdays = command("list_birthdays")
        assert "Bob" not in {b["voornaam"] for b in birthdays}

        # Bob returns in next CSV
        csv_content = make_au_csv([alice_new, MEMBERS[1], MEMBERS[2]])
        command("import_sync", csv_content=csv_content)

        # Bob is to_accept (fully deleted, no account)
        groups = command("compute_groups")
        new_emails = {e["email"] for e in groups["to_accept"]}
        assert "bob@example.com" in new_emails

        # Accept and create bob again
        command("accept_new", email="bob@example.com")
        command("create_accounts", password="Str0ng_T3st_P@ss!2024")
        command("update_existing")

        # Bob can sign in again
        signin = auth_client.create_signin("bob@example.com")
        assert not isinstance(signin, ActionErrorResult)

        # Birthday repopulated
        birthdays = command("list_birthdays")
        by_name = {b["voornaam"]: b for b in birthdays}
        assert "Bob" in by_name
        assert by_name["Bob"]["geboortedatum"] == "20/06/1992"
        assert by_name["Bob"]["tussenvoegsel"] == "de"

    def test_userdata_not_populated_at_account_creation(self, command: Command) -> None:
        """Account creation does not populate userdata or birthdays.

        Spec: update_existing is the only path that populates userdata
        and birthdays. Creating an account alone does not.
        """
        new_member = {
            "Bondsnummer": "2001",
            "Voornaam": "Eve",
            "Achternaam": "NewUser",
            "Geslacht": "V",
            "Geboortedatum": "25/12/2000",
            "Email": "eve@example.com",
        }
        alice_new = {**MEMBERS[0], "Email": "alice.new@example.com"}
        csv_content = make_au_csv([alice_new, MEMBERS[1], MEMBERS[2], new_member])
        command("import_sync", csv_content=csv_content)

        # Accept and create account for eve
        command("accept_new", email="eve@example.com")
        result = command("create_accounts", password="Str0ng_T3st_P@ss!2024")
        assert result["created"] == 1

        # Eve is in existing (registered) with null current userdata
        groups = command("compute_groups")
        eve_pairs = [
            e for e in groups["existing"] if e["sync"]["email"] == "eve@example.com"
        ]
        assert len(eve_pairs) == 1
        assert eve_pairs[0]["current"] is None

        # Eve not in birthdays (not populated until update_existing)
        birthdays = command("list_birthdays")
        assert "Eve" not in {b["voornaam"] for b in birthdays}
