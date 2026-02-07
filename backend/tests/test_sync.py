"""Integration tests for sync operations.

Tests run sequentially within the class, building on each other's state.
The admin user (root_admin@localhost) is bootstrapped at server startup
and auto-marked as a system user (excluded from sync comparison).

Member permission lifecycle:
  1. Signup grants member permission automatically (1-year TTL).
  2. update_existing renews the permission each sync cycle.
  3. remove_departed revokes it when a member leaves.
"""

import csv
import io

from apiserver.sync import parse_csv

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


def make_au_csv(members):
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


def test_parse_csv(tmp_path):
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
    assert entries[0].bondsnummer == "1001"
    assert entries[0].voornaam == "Alice"
    assert entries[0].achternaam == "Smith"
    assert entries[0].opzegdatum == ""
    assert entries[1].tussenvoegsel == "de"
    assert entries[2].email == "charlie@example.com"


def test_parse_csv_with_cancellation():
    """Parse CSV with cancelled member reads opzegdatum."""
    csv_content = make_au_csv([*MEMBERS, CANCELLED_MEMBER])
    entries = parse_csv(csv_content)
    assert len(entries) == 4
    cancelled = [e for e in entries if e.opzegdatum]
    assert len(cancelled) == 1
    assert cancelled[0].email == "diana@example.com"
    assert cancelled[0].opzegdatum == "15/06/2024"


class TestSync:
    """Integration tests for sync operations."""

    def test_import_csv(self, command):
        """Import CSV content into sync table."""
        csv_content = make_au_csv(MEMBERS)
        result = command("import_sync", csv_content=csv_content)
        assert result["imported"] == 3

    def test_compute_groups_admin_excluded(self, command):
        """System user root_admin doesn't appear in departed, 3 new members."""
        result = command("compute_groups")
        assert "root_admin@localhost" not in result["departed"]
        assert len(result["departed"]) == 0
        assert len(result["new"]) == 3

    def test_accept_new(self, command):
        """Accept all new users as board-approved."""
        result = command("accept_new")
        assert result["added"] == 3

    def test_compute_groups_after_accept(self, command):
        """Accepted users move to pending (in newusers, not yet registered)."""
        result = command("compute_groups")
        assert len(result["new"]) == 0
        assert len(result["pending"]) == 3

    def test_create_accounts(self, command):
        """Complete signup for all accepted users (creates real user accounts)."""
        result = command("create_accounts", password="Str0ng_T3st_P@ss!2024")
        assert result["created"] == 3
        assert result["failed"] == 0

    def test_compute_groups_after_registration(self, command):
        """After registration, members show as existing (not new/pending)."""
        result = command("compute_groups")
        assert len(result["new"]) == 0
        assert len(result["pending"]) == 0
        existing_emails = {e["sync"]["email"] for e in result["existing"]}
        assert "alice@example.com" in existing_emails
        assert "bob@example.com" in existing_emails
        assert "charlie@example.com" in existing_emails

    def test_signup_grants_member_permission(self, command):
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

    def test_update_existing_syncs_data(self, command):
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

    def test_cancelled_member_is_departed(self, command):
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

    def test_remove_departed_cancelled(self, command):
        """Remove departed (cancelled) member revokes their permission."""
        result = command("remove_departed", email="alice@example.com")
        assert result["removed"] == 1

        groups = command("compute_groups")
        assert "alice@example.com" not in groups["departed"]

    def test_restore_and_renew(self, command):
        """Re-import all active, update_existing renews alice's permission."""
        csv_content = make_au_csv(MEMBERS)
        command("import_sync", csv_content=csv_content)

        result = command("update_existing")
        assert result["updated"] == 3

        # Verify all 3 have member permission
        command("import_sync", csv_content=make_au_csv([]))
        groups = command("compute_groups")
        departed = set(groups["departed"])
        assert "alice@example.com" in departed
        assert "bob@example.com" in departed
        assert "charlie@example.com" in departed
