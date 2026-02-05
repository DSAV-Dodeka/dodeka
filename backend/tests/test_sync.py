"""Integration tests for sync operations.

Tests run sequentially within the class, building on each other's state.
The admin user (root_admin@localhost) is bootstrapped at server startup
and auto-marked as a system user (excluded from sync comparison).
"""

import csv
import io

from apiserver.sync import parse_csv

# Column names matching the KNHB member export format
KNHB_COLUMNS = [
    "Verenigingscode", "Regio", "Naam vereniging", "Clubnummer", "Bondsnummer",
    "Club lidmaatschap type", "Club lidmaatschap startdatum",
    "Club lidmaatschap einddatum", "Club lidmaatschap opzegdatum",
    "Club lidmaatschap opzegreden", "Bond lidmaatschapstype",
    "Bond lidmaatschap startdatum", "Bond lidmaatschap einddatum",
    "Bond lidmaatschap opzegdatum", "Bond opzegreden",
    "Voornaam", "Tussenvoegsel", "Achternaam", "Initialen", "Geslacht",
    "Geboortedatum", "Nationaliteit", "Straat", "Huisnummer",
    "Huisnummer toevoeging", "Postcode", "Stad", "Landcode",
    "Mobiel", "Telefoon", "Email",
    "Naam ouder 1", "Email ouder 1", "Telefoon ouder 1",
    "Naam ouder 2", "Email ouder 2", "Telefoon ouder 2",
    "Incasso", "Naam bankrekening", "IBAN", "BIC", "Mandaat ID",
    "Mandaat datum", "Contributie termijn", "VOG",
    "_Geef je toestemming om foto's van jou op onze social media te plaatsen?",
    "_Ben je student?",
]


def make_knhb_csv(members):
    """Create CSV content in KNHB export format (without BOM)."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=KNHB_COLUMNS, restval="")
    writer.writeheader()
    for member in members:
        writer.writerow(member)
    return buf.getvalue()


KNHB_MEMBERS = [
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

KNHB_MEMBERS_WITH_ADMIN = [
    *KNHB_MEMBERS,
    {
        "Bondsnummer": "0000",
        "Voornaam": "Root",
        "Achternaam": "Admin",
        "Email": "root_admin@localhost",
    },
]


def test_parse_knhb_csv(tmp_path):
    """Parse a CSV file matching the real KNHB export format (BOM, 47 columns)."""
    csv_content = make_knhb_csv(KNHB_MEMBERS)
    csv_file = tmp_path / "export.csv"
    # Write with UTF-8 BOM like real KNHB exports
    csv_file.write_text(csv_content, encoding="utf-8-sig")

    # Read like the CLI does (default encoding, BOM preserved)
    with open(csv_file) as f:
        content = f.read()

    entries = parse_csv(content)
    assert len(entries) == 3
    assert entries[0].email == "alice@example.com"
    assert entries[0].bondsnummer == "1001"
    assert entries[0].voornaam == "Alice"
    assert entries[0].achternaam == "Smith"
    assert entries[1].tussenvoegsel == "de"
    assert entries[2].email == "charlie@example.com"


class TestSync:
    """Integration tests for sync operations."""

    def test_import_csv_file(self, command, tmp_path):
        """Import from a CSV file matching the real KNHB export format."""
        csv_content = make_knhb_csv(KNHB_MEMBERS)
        csv_file = tmp_path / "export.csv"
        csv_file.write_text(csv_content, encoding="utf-8-sig")

        with open(csv_file) as f:
            content = f.read()

        result = command("import_sync", csv_content=content)
        assert result["imported"] == 3

    def test_admin_auto_marked_system_user(self, command):
        """root_admin is auto-marked as system user during bootstrap."""
        result = command("list_system_users")
        assert "root_admin@localhost" in result["system_users"]

    def test_compute_groups_admin_excluded(self, command):
        """System user root_admin doesn't appear in departed."""
        result = command("compute_groups")
        assert "root_admin@localhost" not in result["departed"]
        assert len(result["departed"]) == 0
        assert len(result["new"]) == 3

    def test_accept_new_single(self, command):
        """Accept a single new user as board-approved."""
        result = command("accept_new", email="alice@example.com")
        assert result["added"] == 1
        assert result["skipped"] == 0

    def test_accept_new_creates_registration_state(self, command):
        """Accepting a user also creates registration_state for signup flow."""
        result = command("check_registration", email="alice@example.com")
        assert result["found"] is True
        assert result["has_signup_token"] is False

    def test_accept_new_all(self, command):
        """Accept remaining new users (alice already accepted -> skipped)."""
        result = command("accept_new")
        assert result["added"] == 2
        assert result["skipped"] == 1

    def test_compute_groups_after_accept(self, command):
        """Accepted users still show as 'new' until they complete signup."""
        result = command("compute_groups")
        # In newusers but not in users_by_email -> still "new"
        assert len(result["new"]) == 3

    def test_initiate_signup(self, command):
        """Full local signup flow: initiate_signup -> get verification token."""
        result = command("initiate_signup", email="alice@example.com")
        assert result["success"] is True

        # Check registration state now has a signup token
        reg = command("check_registration", email="alice@example.com")
        assert reg["found"] is True
        assert reg["has_signup_token"] is True

        # Auth server sends verification email -> token stored via /email handler
        token = command(
            "get_token", action="signup_verification",
            email="alice@example.com",
        )
        assert token["found"] is True
        assert len(token["code"]) > 0

    def test_accept_new_with_signup_batch(self, command):
        """Batch accept-with-signup initiates Faroe signup, email suppressed."""
        # bob and charlie are accepted but have no signup_token yet
        result = command("accept_new_with_signup")
        # All 3 already accepted -> added=0, skipped=3
        assert result["added"] == 0
        assert result["skipped"] == 3
        # bob and charlie need signup (alice already has one)
        assert result["signup_initiated"] == 2
        assert result["signup_failed"] == 0

        # Verify bob has signup_token but 0 emails sent (suppressed)
        reg = command("check_registration", email="bob@example.com")
        assert reg["found"] is True
        assert reg["has_signup_token"] is True

        # Verification token was still stored despite suppression
        token = command(
            "get_token", action="signup_verification",
            email="bob@example.com",
        )
        assert token["found"] is True
        assert len(token["code"]) > 0

    def test_unmark_then_reimport_with_admin(self, command):
        """Unmark admin, reimport with admin email -> admin becomes 'existing'."""
        command("unmark_system_user", email="root_admin@localhost")

        csv_content = make_knhb_csv(KNHB_MEMBERS_WITH_ADMIN)
        result = command("import_sync", csv_content=csv_content)
        assert result["imported"] == 4

        groups = command("compute_groups")
        assert len(groups["departed"]) == 0
        existing_emails = {e["sync"]["email"] for e in groups["existing"]}
        assert "root_admin@localhost" in existing_emails
        assert len(groups["new"]) == 3

    def test_update_existing(self, command):
        """Update existing user's data from sync."""
        result = command("update_existing", email="root_admin@localhost")
        assert result["updated"] == 1

    def test_remove_departed(self, command):
        """Re-import without admin, verify departed, then remove."""
        # Import without admin -> admin becomes departed (still unmarked)
        csv_content = make_knhb_csv(KNHB_MEMBERS)
        result = command("import_sync", csv_content=csv_content)
        assert result["imported"] == 3

        groups = command("compute_groups")
        assert "root_admin@localhost" in groups["departed"]

        # Remove the departed user
        result = command("remove_departed", email="root_admin@localhost")
        assert result["removed"] == 1
