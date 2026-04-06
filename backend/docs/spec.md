# Dodeka Backend Specification

This document specifies the backend identity, sync, registration,
authentication, session, and permission model for D.S.A.V. Dodeka.

It is the authoritative specification for the core backend. Feature-specific
application behavior is out of scope.

## Context

D.S.A.V. Dodeka is a student athletics association. Its backend has to combine
two worlds:

- Dodeka-managed account and permission state
- member data imported from the Dutch athletics federation ecosystem

The imported member data comes from VoltaClub, the administration system used
for Atletiekunie-linked membership administration. The crucial imported
identifier is the `bondsnummer`, the stable Atletiekunie member number.

This backend therefore has to support:

- people who already have a Dodeka account
- people who are known only through a pending registration
- people who are present only in imported Volta data

The specification below is organized around keeping those identities separate
and linking them only through explicit stable identifiers.

## Purpose

The backend exists to do work that cannot safely or cleanly live in the
browser bundle.

It is responsible for:

- server-side logic that must run with trusted credentials or trusted state
- storage and access control for member-only and otherwise private data
- bridging imported Volta/Atletiekunie member data into Dodeka’s member-facing
  system

The frontend must not access raw Volta data directly. Instead, the backend
imports that data, links it to Dodeka identities, applies admin review where
needed, and exposes only the controlled read and write operations that belong
in the Dodeka application.

## Terms

- **Dodeka**: the student association and the Python backend/frontend system
  described by this spec.
- **Atletiekunie**: the Dutch athletics federation whose member numbers are
  used as stable external identity.
- **VoltaClub**: the Atletiekunie-linked administration system used by the
  board. Dodeka imports its CSV export.
- **bondsnummer**: the stable Atletiekunie member number.
- **Faroe** (`tiauth-faroe`): the separate auth server that owns signup,
  signin, password, email-change, and session protocol.
- **freetser**: the SQLite-backed storage layer used by the Python backend.

## Architecture

Two processes cooperate:

- **Python backend**: public HTTP API for the frontend, plus a private HTTP
  server on loopback
- **Faroe auth server**: handles auth protocol and calls back to the Python
  private server

Faroe uses two private callbacks:

- `POST /invoke`: user-server effects against the SQLite-backed user store
- `POST /email`: requests to send auth-related email

All persistent state lives in SQLite behind `freetser.StorageQueue`. Storage
callbacks must remain limited to fast database work. They must not block on
SMTP, HTTP, or filesystem I/O.

## Core Model

### Stable Identifiers

The backend uses three stable identifiers:

- **`registration_id`**: canonical identity of a pending registration
- **`user_id`**: canonical identity of a live account
- **`bondsnummer`**: canonical identity of Volta-managed member data

Normalized email is a mutable lookup key and verified contact channel, not a
stable identity.

### Data Domains

The design is split into two domains.

**Dodeka-managed data**

- owned by the Dodeka backend and Faroe
- keyed by `registration_id` or `user_id`
- examples: registrations, users, password hashes, sessions, permissions

**Volta-managed data**

- owned by sync imports from VoltaClub
- keyed only by `bondsnummer`
- used for member identity linking and member-related imported attributes
- examples: current Volta email, birthday, address details, and potentially
  federation-managed financial information

No separate storage contract is defined for individual Volta-managed fields
beyond `bondsnummer`. Admin and sync APIs work with opaque `VoltaRow` values
and generic field diffs.

This split is the core simplification:

- Dodeka identity does not depend on email stability
- Volta data does not depend on whether the person already has an account
- sync always reasons through `bondsnummer`

### Lifecycle Buckets

Identity-wise, a logical person is in one of these buckets:

1. pending registration, `accepted=False`, no `bondsnummer`
2. pending registration, `accepted=True`, no `bondsnummer`
3. pending registration, `accepted=True`, with `bondsnummer`
4. live user, no `bondsnummer`
5. live user, with `bondsnummer`

These buckets describe the important identity transitions. Additional fields
such as permissions or current signup session state may also exist, but they do
not change the core identity bucket.

Only an accepted registration may become a live user.

## Email Normalization

Email addresses are normalized by:

- trimming surrounding whitespace
- lowercasing

No provider-specific canonicalization is performed.

## Volta Data

### Volta Row

A Volta row is an opaque JSON-like object keyed by `bondsnummer`.

The backend may normalize and expose selected fields such as:

- current Volta email
- names
- cancellation date
- birth date
- address details
- federation-managed financial fields when present

But only `bondsnummer` has special identity semantics. Other Volta-managed
fields are treated generically.

### Imported Snapshot And Applied Volta Data

The backend distinguishes:

- the **latest imported sync snapshot**
- the **currently applied Volta-managed data**

Both are keyed by `bondsnummer`.

This distinction exists so the admin UI can show exact diffs before applying a
new sync.

## Registrations

### Registration Row

The canonical pending-registration row stores:

- `registration_id`
- `email`
- `firstname`
- `lastname`
- `accepted`
- optional `bondsnummer`
- optional `signup_token`

`signup_token` is not the identity of the registration. It is the current
ephemeral Faroe signup-session handle, stored on the registration so the
backend can resume or renew signup from the stable `registration_id`.

Implementations may store additional operational metadata such as email send
counts, but that is not part of the public contract.

### Registration Tables

- `registrations[registration_id] -> RegistrationRow`
- `registrations_by_email[email] -> registration_id`
- `registrations_by_bondsnummer[bondsnummer] -> registration_id`

A registration row is deleted when it successfully becomes a live user.

There is no separate “account created but still pending approval” registration
state in the final model. Acceptance happens before signup completion.

### Public Registration Contract

#### `request_registration(email, firstname, lastname)`

- normalizes the email
- rejects if `users_by_email` already contains the email
- creates a pending registration with `accepted=False` when none exists
- otherwise reuses the existing pending registration for that email
- never clears existing `accepted`, `bondsnummer`, or `signup_token` state on
  reuse
- does not start Faroe signup yet
- returns a generic success response

#### `registration_status(registration_id)`

- resolves the pending registration
- returns whether it exists
- returns whether it is accepted
- returns the current `signup_token` when a Faroe signup session is active,
  otherwise `null`

This endpoint is used after the user follows an email link containing
`registration_id`.

#### `renew_signup(registration_id)`

- resolves the pending registration
- requires `accepted=True`
- starts or renews a Faroe signup for the registration’s current email
- replaces the stored `signup_token`
- sends a fresh signup verification email
- returns the current `signup_token`

This exists because the public Dodeka flow is keyed by stable
`registration_id`, while the Faroe signup flow is keyed by an ephemeral
`signup_token`.

#### `lookup_registration(email, code)`

- normalizes the email
- verifies the current Faroe signup verification code for that email
- resolves `registrations_by_email[email] -> registration_id`
- returns the stable `registration_id`

This is a recovery path when the user has the current email and verification
code but not the invite link.

### Acceptance

Acceptance is what allows a registration to enter Faroe signup.

An admin may accept a registration directly. Sync may also cause a registration
to become accepted by attaching a `bondsnummer` and confirming that it matches
a Volta member.

Accepting a registration:

- sets `accepted=True`
- sends a registration invite email containing `registration_id`

If a registration later gains a `bondsnummer`, it remains the same
`registration_id`.

## Live Users

### Live User Row

A live user has:

- stable `user_id`
- verified email
- Faroe-managed auth state stored through `/invoke`
- optional linked `bondsnummer`

There is no live user without a verified email.

### Creating A Live User

Faroe completes signup by calling `CreateUserEffect` through `/invoke`.

The backend must:

1. normalize the email
2. require `registrations_by_email[email] -> registration_id`
3. require `registrations[registration_id]` with `accepted=True`
4. allocate a new `user_id`
5. create the live user in `users`
6. store the email index in `users_by_email`
7. if the registration has a `bondsnummer`, set
   `users_by_bondsnummer[bondsnummer] -> user_id`
8. grant `member`
9. delete the registration row and its indexes

The live user’s email is now verified and becomes Dodeka-owned.

## Faroe Integration

Faroe owns:

- signup protocol
- signin protocol
- session issuance and validation
- password reset
- email-address verification
- email-address change protocol

The password hash is stored in the Dodeka SQLite-backed user store, not inside
Faroe itself. Faroe reads and writes that state through `/invoke`.

Faroe user-server effects are the named callbacks sent through `/invoke`. In
this spec, `CreateUserEffect` means the signup-completion callback that asks
the backend to create the live user.

### Signup Flow

After the user has an accepted registration and an invite link:

1. frontend opens the link containing `registration_id`
2. frontend calls `registration_status(registration_id)`
3. frontend calls `renew_signup(registration_id)` when needed
4. Faroe sends `signup_verification`
5. frontend calls Faroe directly to:
   - verify the email code
   - set the password
   - complete signup
6. Faroe returns `session_token`
7. frontend calls `POST /cookies/set_session/`

### Signup Email Timing Constraint

When `create_signup(email)` is called, Faroe sends the verification email
through `/email` before the caller has received `signup_token`.

For that reason, invite and signup links use `registration_id`, not
`signup_token`.

That is also why the backend stores the current `signup_token` on the
registration row: the public flow must be resumable from `registration_id`
even though Faroe itself continues through `signup_token`.

## Sync Import

The backend imports a pending Volta snapshot keyed by `bondsnummer`.

Import validation is strict:

- every row must have a positive `bondsnummer`
- every row must have a non-empty normalized email
- duplicate `bondsnummer` values in one import are rejected
- duplicate normalized emails in one import are rejected

The import stage does not itself bind unresolved rows to users or
registrations. That binding happens through the sync review and apply flow.

## Sync Matching Rules

For each imported Volta row, matching is handled in this order:

1. **live user by bondsnummer**
   - if `users_by_bondsnummer[bondsnummer]` exists, the row belongs to that
     live user
2. **pending registration by bondsnummer**
   - if `registrations_by_bondsnummer[bondsnummer]` exists, the row belongs to
     that pending registration
3. **review-required candidates**
   - otherwise, the backend produces possible matches among:
     - live users without `bondsnummer`
     - registrations without `bondsnummer`
   - these are suggestions only
   - the backend must not auto-bind an unresolved row without an existing
     `bondsnummer` link

The only authoritative automatic identity link is an existing `bondsnummer`
mapping.

## Sync Review Candidate Generation

Candidate generation is a review aid, not an automatic identity-binding
mechanism.

For each imported Volta row that has no existing `bondsnummer` link, the
backend must build candidates from exactly this pool:

- live users without `bondsnummer`
- pending registrations without `bondsnummer`

The backend must not search outside that pool.

### Candidate Input Keys

For candidate generation, the backend derives:

- normalized email
- normalized full name
- normalized surname
- normalized given-name prefix key

Email normalization is defined above.

Name normalization for candidate generation is:

- lowercase
- trim surrounding whitespace
- collapse internal whitespace to single spaces

The full name is the normalized space-joined person name used by that row. For
Volta rows this includes the imported given name, optional tussenvoegsel, and
surname. For Dodeka registrations and users it includes the stored first and
last name fields.

The given-name prefix key is the first four normalized characters of the given
name, or the whole given name if it is shorter than four characters.

### Candidate Rules

For one unresolved imported row, the backend must compute candidates in this
order:

1. **exact email**
   - include every candidate whose normalized email equals the imported email
   - add reason `email_exact`
2. **exact full name**
   - include every candidate whose normalized full name equals the imported
     full name
   - add reason `name_exact`
3. **partial name**
   - include candidates whose normalized surname equals the imported surname
     and whose given-name prefix key equals the imported given-name prefix key
   - add reason `name_partial`

If the same subject matches more than one rule, it appears only once and its
`reasons` list contains every matching reason.

### Candidate Ordering And Limit

The backend must return at most five candidates per imported row.

Candidates are ordered by:

1. strongest matching reason:
   - `email_exact`
   - `name_exact`
   - `name_partial`
2. number of matched reasons, descending
3. `kind`, with `"registration"` before `"user"`
4. `subject_id`, ascending lexicographic order

If more than five candidates exist, the backend keeps only the first five after
that ordering.

### Review Contract

The frontend receives the candidate list exactly as returned by the backend and
must send back one explicit admin decision:

- match one candidate registration
- match one candidate live user
- choose “no match”

The backend must not auto-bind an unresolved row based on candidates alone.

## Sync Review Outcomes

For each review-required row, the frontend posts one explicit admin decision.
The backend then performs exactly one of:

- **match an existing registration**
  - set `registrations_by_bondsnummer[bondsnummer]`
  - set `accepted=True`
  - keep the same `registration_id`
- **match an existing live user**
  - set `users_by_bondsnummer[bondsnummer]`
- **no match**
  - create a new accepted registration using the current imported Volta email
  - set `registrations_by_bondsnummer[bondsnummer]`
  - send a registration invite email

If a registration is matched to a `bondsnummer`, it becomes a pending
registration with `accepted=True` and `bondsnummer`.
The linked pending-registration email rule then applies in the same sync apply
cycle.

## Email Rules During Sync

### Linked Pending Registration

If a pending registration already has `bondsnummer`, its email follows the
current Volta email for that `bondsnummer`.

When sync applies a new Volta email to such a registration:

- update the registration email
- rewrite `registrations_by_email`
- clear any stored `signup_token`
- send a fresh registration invite to the new email

This is safe because registration emails are not yet verified and do not own a
live account.

### Linked Live User

If a live user already has `bondsnummer`, sync never rewrites the live account
email.

The Volta email may differ from the account email. That mismatch is visible to
admins but has no automatic effect on the live user. The user must change their
email through Dodeka/Faroe if they want the account email changed.

### Unlinked Registration Or Live User

If no `bondsnummer` link exists yet, sync does not infer identity from email by
itself. It only produces candidates for admin review.

This is the important edge case for self-registration with a different email
from Volta.

## Applying Sync

After review decisions are made, applying sync does three things:

1. update current Volta-managed data by `bondsnummer`
2. apply pending-registration updates for linked registrations
3. refresh Dodeka-owned derived state for linked live users

The first part is unconditional and independent of user lifecycle. The second
part only affects pending registrations already linked by `bondsnummer`. The
third part only affects already linked live users.

### Update Existing

`update_existing` applies the imported Volta snapshot to already linked
identities.

For each pending registration with `bondsnummer` present in the imported
snapshot:

- keep the same `registration_id`
- rewrite the registration email if the Volta email changed
- clear stale signup state when the registration email changes
- send a fresh registration invite when the registration email changes

For each live user with `bondsnummer` present in the imported snapshot:

- refresh current Volta-managed data for that `bondsnummer`
- refresh any Dodeka-owned projections derived from Volta data
- renew `member`

The set of Dodeka-owned projections derived from Volta data is
implementation-defined. The admin API must nevertheless expose generic field
diffs for all Volta-managed fields.

## Departed Members

`remove_departed` only applies to live users with `bondsnummer`.

A live user is departed when:

- their `bondsnummer` is no longer present in the imported snapshot, or
- the imported Volta row marks the membership as cancelled

For each departed linked live user, the backend:

1. deletes the user row
2. deletes `users_by_email`
3. deletes `users_by_bondsnummer`
4. deletes any Dodeka-managed per-user data

Live users without `bondsnummer` are never auto-removed by sync because sync
has no authoritative identity link for them.

## Important Cases

### Self-Registration Before Sync

A self-registered person starts as:

- pending registration
- `accepted=False`
- no `bondsnummer`

If sync later identifies them through an admin-confirmed match:

- the same registration row is kept
- `accepted=True`
- `bondsnummer` is attached
- the registration invite goes to the current Volta email

### Self-Registration With Different Volta Email

If the self-registration email and Volta email differ, and there is no
`bondsnummer` link yet:

- the backend does not auto-merge them
- sync returns candidates
- the admin must explicitly confirm the match or choose “no match”

This is the explicit recovery path for the hardest pre-account email-change
case.

### Volta Email Change Before Signup Completion

If a pending registration already has `bondsnummer` and the Volta email later
changes:

- the same `registration_id` remains valid
- the registration email is updated to the current Volta email
- stale signup state is cleared
- the next invite or renewed signup goes to the new email

### Volta Email Change After Account Creation

If a live user already has `bondsnummer` and the Volta email changes:

- sync does not modify the account email
- the mismatch is visible in admin read models
- the user must change email through the normal Dodeka/Faroe account flow

## Admin Read Models

The admin UI depends on structured read models. These are part of the backend
contract.

At minimum:

- `list_users` returns `AdminUserRecord[]`
- `list_registrations` returns `AdminRegistrationRecord[]`
- `sync_status` returns `SyncStatus`

### `AdminUserRecord`

For each live user:

- `user_id`
- `email`
- `firstname`
- `lastname`
- `permissions`
- optional `bondsnummer`
- `volta_data: VoltaRow | null`

### `AdminRegistrationRecord`

For each pending registration:

- `registration_id`
- `email`
- `firstname`
- `lastname`
- `accepted`
- optional `bondsnummer`
- `signup_active`
- `volta_data: VoltaRow | null`

This is the read model for general registration admin pages, not the sync
preview.

### `SyncMatchCandidate`

One candidate suggested for admin review:

- `kind` (`"registration"` or `"user"`)
- `subject_id`
- `email`
- `display_name`
- `reasons`

`reasons` is a non-empty ordered list from this closed set:

- `email_exact`
- `name_exact`
- `name_partial`

The list is ordered from strongest to weakest reason.

### `VoltaFieldDiff`

One generic Volta-managed field difference:

- `field`
- `current`
- `incoming`

### `ExistingSyncRecord`

For one linked live user during sync preview:

- `bondsnummer`
- `user: AdminUserRecord`
- `current_volta_data`
- `incoming_volta_data`
- `field_diffs: VoltaFieldDiff[]`

### `PendingRegistrationSyncRecord`

For one linked pending registration during sync preview:

- `bondsnummer`
- `registration: AdminRegistrationRecord`
- `current_volta_data`
- `incoming_volta_data`
- `field_diffs: VoltaFieldDiff[]`
- `email_will_change`

### `SyncReviewItem`

For one unresolved imported row:

- `bondsnummer`
- `incoming_volta_data`
- `candidates: SyncMatchCandidate[]`

### `SyncStatus`

The sync preview response must return:

- `review_required: SyncReviewItem[]`
- `linked_registrations: PendingRegistrationSyncRecord[]`
- `existing: ExistingSyncRecord[]`
- `departed: AdminUserRecord[]`

This is what the admin frontend uses to explain the exact effects of the next
sync apply step.

### `Update Existing` Result

`update_existing` may return top-level counts, but it must also return enough
structured detail for the frontend to report exactly what changed.

At minimum, the result must identify:

- which `bondsnummer` rows were applied
- which linked pending registrations were updated
- which linked live users were refreshed
- the `field_diffs` that were applied for each updated registration or
  refreshed live user

## Sessions And Permissions

### Member Permission

`member` is granted when an accepted registration successfully becomes a live
user.

For linked live users, sync renews `member` on successful `update_existing`.

### Signin

Signin is Faroe-driven:

1. frontend calls `create_signin(email)`
2. frontend calls `verify_signin_user_password(signin_token, password)`
3. frontend calls `complete_signin(signin_token)`
4. Faroe returns `session_token`
5. frontend calls `POST /cookies/set_session/`

### Session Validation

Validated Faroe sessions may be cached in `session_cache`, but access checks
must still load current Dodeka user state after session validation.

That is what makes deleted users lose access immediately even if session
validation itself was cached.

### `session_info`

`session_info` returns the current live user identity and permissions derived
from the validated session.

It returns:

- `user_id`
- `email`
- `firstname`
- `lastname`
- `permissions`

It does not return a `pending_approval` flag in the final model. Pending
approval is represented only by pending registrations, not by a partially live
user state.

## Email Notifications

There are two categories of email.

**Backend-initiated**

- `registration_invite`

This is sent when:

- a registration is manually accepted
- sync creates a new accepted registration
- sync updates the email of a pending registration that already has
  `bondsnummer`

The link contains `registration_id`.

**Faroe-initiated**

- `signup_verification`
- `email_update_verification`
- `password_reset`
- `signin_notification`
- `password_updated`
- `email_updated`

## Admin Operations

The core admin operations are:

- `import_sync`
- `sync_status`
- `accept_registration`
- `resolve_sync_match`
- `link_bondsnummer`
- `update_existing`
- `remove_departed`

### `import_sync`

`import_sync` replaces the pending imported snapshot with a newly parsed
VoltaClub CSV import.

It:

- validates the import
- stores the imported rows as the new pending snapshot
- does not itself create, delete, or relink registrations or users

The replacement is atomic from the perspective of later `sync_status`,
`resolve_sync_match`, `update_existing`, and `remove_departed` calls.

### `sync_status`

`sync_status` is a read-only preview over:

- the pending imported snapshot
- current live users
- current pending registrations
- current applied Volta-managed data

It returns `SyncStatus`.

### `accept_registration`

`accept_registration` is the direct admin path for a pending registration that
does not require sync review.

It:

- resolves the pending registration by `registration_id`
- sets `accepted=True`
- sends a registration invite email to the registration’s current email

If the registration already has `accepted=True`, the operation is idempotent.

### `resolve_sync_match`

`resolve_sync_match` applies one explicit admin decision for one unresolved
imported `bondsnummer` row.

It supports exactly these outcomes:

- match one pending registration by `registration_id`
- match one live user by `user_id`
- choose “no match” and create a new accepted registration

It updates the canonical registration/user links immediately. There is no
separate persisted review-decisions table in the final model.

Concretely, it must write one of:

- `registrations_by_bondsnummer[bondsnummer] -> registration_id`
- `users_by_bondsnummer[bondsnummer] -> user_id`

and any accompanying registration changes required by the chosen outcome.

It must fail if the supplied `bondsnummer` row is not present in the current
pending imported snapshot, or if the chosen outcome conflicts with an existing
different `bondsnummer` link.

After a successful `resolve_sync_match`, the next `sync_status` call must no
longer report that `bondsnummer` in `review_required`.

### `link_bondsnummer`

`link_bondsnummer` is the explicit recovery path for unresolved identity
problems.

It must support:

- linking a pending registration by `registration_id`
- linking a live user by `user_id`

It:

- assigns the supplied `bondsnummer`
- writes the appropriate bondsnummer index
- fails if that `bondsnummer` is already linked to a different identity

Linking a registration by `bondsnummer` does not itself create a live user. It
only moves that registration into the “accepted registration with bondsnummer”
bucket.

## Core Tables

| Table | Key | Value | Purpose |
|---|---|---|---|
| `users` | `{user_id}:{field}` | varies | Dodeka/Faroe-managed live user state |
| `users_by_email` | normalized email | user_id | Live user email index |
| `users_by_bondsnummer` | `str(bondsnummer)` | user_id | Live user Volta identity link |
| `registrations` | `registration_id` | `RegistrationRow` | Canonical pending registration state |
| `registrations_by_email` | normalized email | `registration_id` | Pending registration email index |
| `registrations_by_bondsnummer` | `str(bondsnummer)` | `registration_id` | Pending registration Volta identity link |
| `sync` | `str(bondsnummer)` | `VoltaRow` | Latest imported Volta snapshot pending review/apply |
| `volta_data` | `str(bondsnummer)` | `VoltaRow` | Current applied Volta-managed data |
| `metadata` | key | value | Global counters and backend metadata |
| `system_users` | normalized email | `b"1"` | Users excluded from sync departure checks |
| `session_cache` | `session_token` | session JSON | Cache of validated Faroe sessions |
| `tokens` | `{kind}:{email}` | auxiliary token data | Local testing/tooling mirror for verification codes |
