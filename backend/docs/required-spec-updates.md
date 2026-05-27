# Required Spec Updates

Notes on places where the implementation deviates from or clarifies
`spec.md`.

## 1. `link_bondsnummer` sets `accepted=True` on registrations

The spec says `link_bondsnummer` "only moves that registration into the
'accepted registration with bondsnummer' bucket." The implementation
interprets this as also setting `accepted=True`, since bucket 3 in the
lifecycle is defined as `accepted=True, with bondsnummer`.

Without this, a registration linked via `link_bondsnummer` would remain
`accepted=False` and could not enter Faroe signup via `renew_signup`.

## 2. `complete_sync` requires all review items resolved

The spec says `complete_sync` "fails if `review_required` is non-empty".
This means every unlinked imported row must have a `resolve_sync_match`
decision recorded before `complete_sync` can proceed.

The birthday rebuild test was updated to add a `resolve_sync_match` for
the unlinked person row before calling `complete_sync`, since the test
originally expected `complete_sync` to succeed with unresolved rows.

## 3. `volta_data_changes` includes all imported rows

The `SyncStatus.volta_data_changes` list includes every imported row,
not just rows with actual diffs. This shows the full picture of what
`complete_sync` will write to `volta_data`, including new insertions.
Rows present in current `volta_data` but absent from the import are also
included with `incoming_volta_data: null` to represent removals.

## 4. `drain_outbox_since` not exposed as HTTP route

The spec requires operator tooling for `drain_outbox_since(since)`. The
function exists in `handlers/acceptance.py` but is only callable through
the private command interface, not a public admin HTTP route.

## 5. Departed registrations not tracked by sync

The `departed_users` list in sync status only includes live users (those
who completed signup and exist in the bondsnummer table). Registrations
that are linked to a bondsnummer but have not completed signup (i.e.
accepted/invited registrations) are **not** reported as departed when
their bondsnummer disappears from the import or is cancelled.

This means if someone was accepted+invited but never created their
account, and they later leave the club, their registration will silently
remain in the system. `complete_sync` will not clean it up.

The spec does not cover this case. A future enhancement could add a
`departed_registrations` category to sync status, or `complete_sync`
could clear `accepted` / unlink bondsnummers for these registrations.

## 6. Frontend category names differ from backend field names

The admin frontend uses human-readable names that differ from the
backend JSON field names:

| Backend field                    | Admin UI label           |
|----------------------------------|--------------------------|
| `review_required`                | Review required          |
| `registrations_created`          | New registrations        |
| `registrations_accepted`         | Matched registrations    |
| `pending_registrations_updated`  | Existing registrations   |
| `live_users_enriched`            | Current members          |
| `departed_users`                 | Departed members         |
| `volta_data_changes`             | Import data overview     |

`live_users_enriched` contains members still present in the import.
`complete_sync` refreshes their profile data and renews their `member`
permission. The admin does not need to know about internal data table
names or "enrichment" — from their perspective these are confirmed
current members.
