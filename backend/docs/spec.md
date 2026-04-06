# Dodeka Backend Specification

This document specifies the backend identity, sync, registration,
authentication, session, and permission model for D.S.A.V. Dodeka.

It is the authoritative specification for the core backend. Feature-specific
application behavior is out of scope.

## Context

D.S.A.V. Dodeka is a student athletics association. Its backend has to combine
two worlds:

- Dodeka-managed account and permission state
- member data imported from the Dutch athletics federation system

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

Because one `freetser` storage callback runs serially and transactionally,
larger state transitions should be implemented as one callback composed from
smaller storage-only helper functions. Those helper functions may call each
other freely as long as they do not perform external side effects.

### Durable Backend Side Effects

Some external effects are safe to retry by repeating the same request or
public flow. Those do not need durable storage.

Other effects must still happen after a canonical state change has committed
even if the original request is gone. Those effects must be written as
internal durable `outbox` rows in the same `freetser` storage callback as the
canonical mutation. Delivery happens only after commit and therefore has
at-least-once semantics, not exactly-once semantics. Outbox-backed emails such
as registration invites must tolerate duplicates.

The outbox is internal. Admin-performable operations such as
`resend_registration_invite` are separate commands, not direct views onto the
outbox.

The backend must run an automatic outbox dispatcher once on startup and then at
least once per minute while healthy. Each pass selects rows with
`status = "pending"`, `next_attempt_at <= now`, and `created_at > now - 8
hours`.

Retry timing is fixed:

- new row: `attempt_count = 0`, `next_attempt_at = created_at`
- after failures: retry in `1 minute`, then `5 minutes`, then `30 minutes`,
  then every `2 hours`
- if the next automatic retry would be at or after `created_at + 8 hours`,
  stop automatic retry and mark the row `manual_retry_required`

Older rows are retried only through operator tooling such as
`drain_outbox_since(since)`.

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
- the **pending admin match decisions for that snapshot**
- the **currently applied Volta-managed data**

The imported snapshot and the applied Volta data are both keyed by
`bondsnummer`. The pending decisions are keyed by `bondsnummer` and record one
explicit admin outcome for unresolved imported rows.

This distinction exists so the admin UI can show exact diffs before applying a
new sync.

Only one pending sync session may exist at a time.

That pending sync session consists of:

- the singleton `sync_state["current"]` row
- the imported snapshot in `sync`
- the pending decisions in `sync_decisions`
- the built-in `freetser` counter of `sync_state["current"]`, used to reject
  stale overwrite, decision, and completion requests

`sync_state["current"]` stores whether a pending sync session exists. Its
built-in counter changes whenever that row is updated, which is how clients
detect stale sync operations across separate requests.

### Derived Tables From Applied Volta Data

Some Dodeka-owned read models are derived from applied Volta data rather than
stored independently.

The concrete example in this spec is the birthdays table:

- it is keyed by `user_id`
- it is derived from `volta_data`, not from the pending `sync` snapshot
- it is rebuilt by iterating the applied `volta_data` rows, resolving
  `users_by_bondsnummer[bondsnummer] -> user_id`, and computing one birthday
  row for each linked live user
- rows with no linked live user are omitted
- the whole birthdays table is replaced atomically during `complete_sync`
- if a new live user is created later from an already linked accepted
  registration, the derived row for that `user_id` must also be populated from
  the already applied `volta_data`

This pattern generalizes to future Dodeka-owned projections derived from
Volta-managed data.

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
state in this spec. Acceptance happens before signup completion.

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

`renew_signup` is a request-coupled effect, not an outbox-backed effect. If
it fails, the same `registration_id` flow can safely trigger it again.

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

Accepting a registration that is not yet accepted:

- sets `accepted=True`
- creates one durable `send_registration_invite` outbox row for that
  `registration_id`

If a registration later gains a `bondsnummer`, it remains the same
`registration_id`.

Repeating acceptance for an already accepted registration is idempotent and
must not create a duplicate automatic outbox invite.

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
8. if that `bondsnummer` already exists in applied `volta_data`, refresh any
   per-user projections derived from Volta data for the new live user
9. grant `member`
10. delete the registration row and its indexes

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
The backend then records exactly one pending outcome in the sync tables:

- **match an existing registration**
  - remember `registration_id` as the chosen target for that imported
    `bondsnummer`
- **match an existing live user**
  - remember `user_id` as the chosen target for that imported `bondsnummer`
- **no match**
  - remember that `complete_sync` must create a new accepted registration for
    that imported `bondsnummer`

Recording a sync decision must not itself mutate canonical registrations,
canonical user links, applied `volta_data`, or send email.

Those canonical changes happen only during `complete_sync`.

Registrations created or matched through sync still become accepted because the
imported Volta row is authoritative membership evidence, but that acceptance is
part of the atomic completion step, not part of recording the decision.

## Email Rules During Sync

### Linked Pending Registration

If a pending registration already has `bondsnummer`, its email follows the
current Volta email for that `bondsnummer`.

When `complete_sync` applies a new Volta email to such a registration:

- update the registration email
- rewrite `registrations_by_email`
- clear any stored `signup_token`
- create a fresh durable outbox row for a registration invite to the new email

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

## Completing Sync

After review decisions are made, `complete_sync` applies the pending sync
session in one atomic `freetser` storage callback.

It does five things:

1. replace the applied `volta_data` with the imported snapshot
2. apply the pending match decisions to registrations and live-user
   bondsnummer links
3. apply pending-registration email rewrites, live-user profile refreshes, and
   member renewals
4. remove departed linked live users
5. rebuild Dodeka-owned derived tables from the newly applied `volta_data`

The imported snapshot becomes the new current Volta truth only when
`complete_sync` succeeds. Until then, `volta_data` remains the last completed
snapshot.

The database effects of `complete_sync` are atomic because they happen inside
one storage callback. The callback may be internally composed from pure storage
helpers such as:

- replacing the applied `volta_data`
- applying one stored sync decision
- updating one linked registration
- refreshing one linked live user
- removing one departed live user
- rebuilding one derived table

SMTP is not part of that atomic database transaction. Any backend-owned invite
emails needed by `complete_sync` must therefore be created as durable outbox
rows during the callback. Those rows may be attempted after the successful
commit, but delivery retry is defined by the durable side-effect rules above
rather than by the first send attempt succeeding.

### Registration Effects During `complete_sync`

For each existing registration chosen during sync review:

- keep the same `registration_id`
- set `accepted=True`
- set the final `bondsnummer`
- rewrite the registration email to the imported Volta email if needed
- clear stale signup state if the email changes
- create one durable registration-invite outbox row for the final
  registration email

For each `"no match"` decision:

- create a new accepted registration using the current imported Volta email
- set its `bondsnummer`
- create one durable registration-invite outbox row

For each already linked pending registration whose imported Volta email changed:

- keep the same `registration_id`
- rewrite the registration email
- clear stale signup state
- create a fresh durable registration-invite outbox row

### Live User Effects During `complete_sync`

For each live user with `bondsnummer` present in the imported snapshot and not
cancelled:

- keep the same `user_id`
- keep the same account email
- refresh Dodeka-owned profile data derived from Volta data
- renew `member`

This applies both to already linked live users and to live users chosen during
sync review.

## Departed Members

Departed-member handling is part of `complete_sync`, not a separate sync apply
step.

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
- `complete_sync` sets `accepted=True`
- `complete_sync` attaches `bondsnummer`
- `complete_sync` creates a registration-invite outbox row for the current
  Volta email

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
- `complete_sync` updates the registration email to the current Volta email
- `complete_sync` clears stale signup state
- the next outbox-backed invite or renewed signup uses the new email

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
- `available_actions: RegistrationAction[]`

This is the read model for general registration admin pages, not the sync
preview.

### `RegistrationAction`

One action that can be started directly from the registrations admin page.
These are user-triggered admin operations, not durable outbox rows.

- `kind`

Currently the closed set is:

- `resend_registration_invite`

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

`current` and `incoming` may be `null` when the diff represents full-row
insertion or removal.

### `LiveUserSyncRecord`

For one live user that will be enriched during `complete_sync`:

- `bondsnummer`
- `user: AdminUserRecord`
- `current_volta_data`
- `incoming_volta_data`
- `field_diffs: VoltaFieldDiff[]`

### `PendingRegistrationSyncRecord`

For one pending registration that will be accepted or updated during
`complete_sync`:

- `bondsnummer`
- `registration: AdminRegistrationRecord`
- `current_volta_data`
- `incoming_volta_data`
- `field_diffs: VoltaFieldDiff[]`
- `email_will_change`

### `CreatedRegistrationSyncRecord`

For one new accepted registration that `complete_sync` will create:

- `bondsnummer`
- `email`
- `firstname`
- `lastname`
- `incoming_volta_data`

### `VoltaDataSyncRecord`

For one applied Volta row that will be inserted, replaced, or removed during
`complete_sync`:

- `bondsnummer`
- `current_volta_data`
- `incoming_volta_data`
- `field_diffs: VoltaFieldDiff[]`

### `SyncDecision`

One persisted sync-review decision:

- `kind` (`"registration"`, `"user"`, or `"none"`)
- `subject_id`

`subject_id` is `null` only for `"none"`.

### `SyncStateRow`

The singleton sync-session state row stored at `sync_state["current"]`:

- `in_progress: boolean`

The optimistic concurrency token for sync operations is not stored in the row
payload. It is the built-in `freetser` counter returned alongside that row.

### `OutboxRow`

One internal durable backend side-effect row:

- `outbox_id`
- `kind`
- `status`
- `subject_kind`
- `subject_id`
- `payload`
- `created_at`
- optional `last_attempt_at`
- `next_attempt_at`
- `attempt_count`
- optional `last_error`

Current `status` values are:

- `pending`
- `succeeded`
- `manual_retry_required`

Status meanings are:

- `pending`: not yet delivered and still tracked by the automatic retry
  schedule
- `succeeded`: delivered successfully
- `manual_retry_required`: not delivered and no longer eligible for automatic
  retry

While a row is still within the automatic retry window, a failed attempt keeps
it in `pending` and updates `next_attempt_at` to the next scheduled retry
time. When the automatic window closes without success, the row becomes
`manual_retry_required`. A successful manual replay changes the row to
`succeeded`; a failed manual replay leaves it `manual_retry_required`.

The current closed set of durable outbox kinds is:

- `send_registration_invite`

### `SyncReviewItem`

For one unresolved imported row:

- `bondsnummer`
- `incoming_volta_data`
- `candidates: SyncMatchCandidate[]`

### `SyncStatus`

The sync preview response must return:

- `sync_in_progress: boolean`
- `sync_state_counter: int`
- `can_complete: boolean`
- `review_required: SyncReviewItem[]`
- `registrations_created: CreatedRegistrationSyncRecord[]`
- `registrations_accepted: PendingRegistrationSyncRecord[]`
- `pending_registrations_updated: PendingRegistrationSyncRecord[]`
- `live_users_enriched: LiveUserSyncRecord[]`
- `departed_users: AdminUserRecord[]`
- `volta_data_changes: VoltaDataSyncRecord[]`

This is what the admin frontend uses to explain the exact effects of the next
sync completion step.

### `Complete Sync` Result

`complete_sync` may return top-level counts, but it must also return enough
structured detail for the frontend to report exactly what changed.

At minimum, the result must identify:

- which Volta rows were inserted, replaced, or removed
- which registrations were created
- which registrations were accepted
- which pending registrations were updated
- which live users were refreshed
- which live users were removed as departed

## Sessions And Permissions

### Member Permission

`member` is granted when an accepted registration successfully becomes a live
user.

For linked live users, sync renews `member` on successful `complete_sync`.

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

It does not return a `pending_approval` flag in this spec. Pending
approval is represented only by pending registrations, not by a partially live
user state.

## Email Notifications

There are two categories of email.

**Durable backend-owned registration invite email**

This is the email semantic used to continue signup from `registration_id`.
The current implementation uses the existing email type identifier
`sync_please_register`.

Whether a particular flow writes a durable outbox row or sends immediately is
defined in that flow’s own section. When an invite is outbox-backed, the
canonical state change writes the outbox row atomically and the backend
retries delivery according to the durable side-effect rules above.

The link contains `registration_id`.

**Faroe-owned request-coupled email**

These emails are part of Faroe flows, not Dodeka outbox-backed delivery. They
are retried by repeating the Faroe-triggering flow rather than by replaying an
outbox row.

`renew_signup` is the important example: it asks Faroe to send
`signup_verification`, and revisiting the same `registration_id` flow retries
that request if needed.

The current Faroe-owned set is:

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
- `resend_registration_invite`
- `resolve_sync_match`
- `link_bondsnummer`
- `complete_sync`

### `import_sync`

`import_sync` starts or overwrites the single pending sync session with a newly
parsed VoltaClub CSV import.

It:

- validates the import
- returns either an imported-row count or a structured validation error from
  the storage helper
- runs as one storage callback
- updates `sync_state["current"]` to `{"in_progress": true}`
- stores the imported rows as the new pending snapshot in `sync`
- clears any older pending review decisions in `sync_decisions`
- does not itself create, delete, relink, accept, or email any registrations
  or users

The HTTP admin handler maps the validation-error case to HTTP 400.

If a pending sync session already exists, the client must explicitly confirm
that overwrite against the current `sync_state_counter`.

### `sync_status`

`sync_status` is a read-only preview over:

- the pending imported snapshot
- the pending sync-review decisions
- current live users
- current pending registrations
- current applied Volta-managed data

It returns `SyncStatus`.

If no pending sync session exists, `sync_in_progress` is `false`,
`can_complete` is `false`, and every preview list is empty.

### `accept_registration`

`accept_registration` is the direct admin path for a pending registration that
does not require sync review.

It:

- resolves the pending registration by `registration_id`
- sets `accepted=True`
- writes one durable `send_registration_invite` outbox row for the
  registration’s current email in the same storage callback

If the registration already has `accepted=True`, the operation is idempotent
and must not create a duplicate automatic outbox invite.

This uses the outbox because the acceptance commit must imply eventual invite
delivery even if the backend crashes after the storage callback succeeds.

### `resend_registration_invite`

`resend_registration_invite` is the manual admin path exposed on the
registrations page.

It:

- resolves the pending registration by `registration_id`
- requires `accepted=True`
- sends a fresh registration invite immediately to the registration’s current
  email
- returns an error to the admin caller if immediate delivery fails

This operation does not change the registration’s canonical identity state.
It does not use the outbox because the admin caller is already the retry path.

### `resolve_sync_match`

`resolve_sync_match` records one explicit admin decision for one unresolved
imported `bondsnummer` row.

It supports exactly these outcomes:

- match one pending registration by `registration_id`
- match one live user by `user_id`
- choose “no match” and create a new accepted registration during
  `complete_sync`

It writes or replaces exactly one pending decision in `sync_decisions`.

A successful `resolve_sync_match` must also update `sync_state["current"]`, so
its built-in counter advances.

This recording step must run as one storage callback. It may call pure
validation and write helpers internally, but it must not perform SMTP or other
external side effects.

It must fail if the supplied `bondsnummer` row is not present in the current
pending imported snapshot, if the chosen target does not exist, if the chosen
outcome conflicts with an existing different `bondsnummer` link, or if the
supplied `sync_state_counter` is stale.

After a successful `resolve_sync_match`, the next `sync_status` call must no
longer report that `bondsnummer` in `review_required` unless the stored
decision later becomes invalid against the current canonical state.

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
- fails if the chosen registration or user is already linked to a different
  `bondsnummer`

Linking a registration by `bondsnummer` does not itself create a live user. It
only moves that registration into the “accepted registration with bondsnummer”
bucket.

### `complete_sync`

`complete_sync` applies the current pending sync session to canonical backend
state.

It:

- requires the current `sync_state_counter`
- fails if no pending sync session exists
- fails if `review_required` is non-empty
- replaces `volta_data` with the imported snapshot
- applies the pending sync decisions to registrations and live-user links
- applies linked-registration email rewrites
- refreshes linked live-user profile data and renews `member`
- removes departed linked live users
- rebuilds derived tables such as birthdays
- updates `sync_state["current"]` to `{"in_progress": false}`
- clears `sync` and `sync_decisions`

`complete_sync` should be implemented by composing storage-only helper
functions inside that one callback. No extra application-level transaction
mechanism is needed beyond `freetser`'s storage callback semantics and the
optimistic counter check on `sync_state["current"]`.

Outbox rows created by `complete_sync` may be attempted immediately after the
successful commit, but delivery guarantees come from the outbox retry rules
rather than from that first attempt succeeding. No other `complete_sync`
effects use the outbox in this spec.

## Operational Tooling

The backend must also expose operator tooling for bulk replay of durable
outbox rows. This is not required to be a public frontend route.

At minimum, the tooling contract must include:

- `drain_outbox_since(since)`

`drain_outbox_since(since)` attempts every outbox row with `status !=
"succeeded"` and `created_at >= since`.

It must process those rows in ascending `created_at` order and update
`last_attempt_at`, `attempt_count`, and `last_error` exactly like the
automatic dispatcher. It ignores the eight-hour automatic cutoff.

This exists for recovery after crashes, power loss, outages, or long SMTP
failures:

- automatic replay only covers outbox rows younger than eight hours
- operator tooling supports bulk replay for older outbox rows from a specified
  date or timestamp

## Core Tables

| Table | Key | Value | Purpose |
|---|---|---|---|
| `users` | `{user_id}:{field}` | varies | Dodeka/Faroe-managed live user state |
| `users_by_email` | normalized email | user_id | Live user email index |
| `users_by_bondsnummer` | `str(bondsnummer)` | user_id | Live user Volta identity link |
| `registrations` | `registration_id` | `RegistrationRow` | Canonical pending registration state |
| `registrations_by_email` | normalized email | `registration_id` | Pending registration email index |
| `registrations_by_bondsnummer` | `str(bondsnummer)` | `registration_id` | Pending registration Volta identity link |
| `outbox` | `outbox_id` | `OutboxRow` | Internal durable backend side effects and retry state |
| `sync_state` | `current` | `SyncStateRow` | Singleton pending-sync state row whose built-in `freetser` counter is the sync revision |
| `sync` | `str(bondsnummer)` | `VoltaRow` | Imported Volta snapshot for the single pending sync session |
| `sync_decisions` | `str(bondsnummer)` | `SyncDecision` | Pending review decisions for unresolved imported rows |
| `volta_data` | `str(bondsnummer)` | `VoltaRow` | Current applied Volta-managed data from the last completed sync |
| `metadata` | key | value | Global counters and backend metadata |
| `system_users` | normalized email | `b"1"` | Users excluded from sync departure checks |
| `session_cache` | `session_token` | session JSON | Cache of validated Faroe sessions |
| `tokens` | `{kind}:{email}` | auxiliary token data | Local testing/tooling mirror for verification codes |
